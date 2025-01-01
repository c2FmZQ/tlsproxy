// MIT License
//
// Copyright (c) 2024 TTBT Enterprises LLC
// Copyright (c) 2024 Robin Thellend <rthellend@rthellend.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package cloudflare

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
)

type Target struct {
	Token string   `yaml:"token"`
	Zone  string   `yaml:"zone"`
	Names []string `yaml:"names"`
}

type zoneName struct {
	Zone string
	Name string
}

type idData struct {
	ZoneID   string
	RecordID string
	Data     httpsData
}

type httpsData struct {
	Priority int    `json:"priority"`
	Target   string `json:"target"`
	Value    string `json:"value"`
}

func UpdateECH(records []*Target, configList string, logger func(string, ...any)) {
	zones := make(map[string]bool)
	data := make(map[zoneName]idData)
	re := regexp.MustCompile(` *ech=[^ ]*`)
	for _, r := range records {
		if !zones[r.Zone] {
			zones[r.Zone] = true
			if err := getZoneData(r.Token, r.Zone, data); err != nil {
				logger("ERR cloudflare [%s]: %v", r.Zone, err)
				continue
			}
		}
		for _, name := range r.Names {
			v, exists := data[zoneName{r.Zone, name}]
			if !exists {
				logger("ERR cloudflare [%s] %s doesn't exist", r.Zone, name)
				continue
			}
			value := re.ReplaceAllString(v.Data.Value, "") + ` ech="` + configList + `"`
			if value == v.Data.Value {
				logger("INF cloudflare [%s] %s: no change", r.Zone, name)
				continue
			}
			v.Data.Value = value
			if err := updateRecord(r.Token, v.ZoneID, v.RecordID, v.Data); err != nil {
				logger("ERR cloudflare [%s] %s: %v", r.Zone, name, err)
			}
			logger("INF cloudflare [%s] %s: updated", r.Zone, name)
		}
	}
}

func getZoneData(token, zone string, data map[zoneName]idData) error {
	u := url.URL{
		Scheme: "https",
		Host:   "api.cloudflare.com",
		Path:   "/client/v4/zones",
	}
	q := u.Query()
	q.Set("name", zone)
	u.RawQuery = q.Encode()
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var result struct {
		Success bool `json:"success"`
		Result  []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"result"`
	}
	if err := json.Unmarshal(b, &result); err != nil {
		return err
	}
	if !result.Success || len(result.Result) == 0 {
		return errors.New("not found")
	}
	zoneID := result.Result[0].ID

	for page := 1; ; page++ {
		u := url.URL{
			Scheme: "https",
			Host:   "api.cloudflare.com",
			Path:   "/client/v4/zones/" + zoneID + "/dns_records",
		}
		q := u.Query()
		q.Set("type", "HTTPS")
		q.Set("per_page", "20")
		q.Set("page", strconv.Itoa(page))
		u.RawQuery = q.Encode()
		req, err = http.NewRequest("GET", u.String(), nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		b, _ = io.ReadAll(resp.Body)
		var result struct {
			Success bool `json:"success"`
			Result  []struct {
				ID   string    `json:"id"`
				Name string    `json:"name"`
				Data httpsData `json:"data"`
			} `json:"result"`
			ResultInfo struct {
				Count   int `json:"count"`
				Page    int `json:"page"`
				PerPage int `json:"per_page"`
			} `json:"result_info"`
		}
		if err := json.Unmarshal(b, &result); err != nil {
			return err
		}
		if !result.Success {
			return errors.New("not found")
		}
		for _, r := range result.Result {
			data[zoneName{zone, r.Name}] = idData{zoneID, r.ID, r.Data}
		}
		if len(result.Result) == 0 || result.ResultInfo.Page*result.ResultInfo.PerPage >= result.ResultInfo.Count {
			break
		}
	}
	return nil
}

func updateRecord(token, zoneID, recordID string, data httpsData) error {
	b, err := json.Marshal(struct {
		Data httpsData `json:"data"`
	}{Data: data})
	if err != nil {
		return err
	}
	u := url.URL{
		Scheme: "https",
		Host:   "api.cloudflare.com",
		Path:   "/client/v4/zones/" + zoneID + "/dns_records/" + recordID,
	}
	req, err := http.NewRequest("PATCH", u.String(), bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ = io.ReadAll(resp.Body)
	var result struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(b, &result); err != nil {
		return err
	}
	if !result.Success {
		return errors.New("failed")
	}
	return nil
}
