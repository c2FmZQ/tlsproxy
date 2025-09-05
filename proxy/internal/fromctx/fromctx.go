// MIT License
//
// Copyright (c) 2025 TTBT Enterprises LLC
// Copyright (c) 2025 Robin Thellend <rthellend@rthellend.com>
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

package fromctx

import (
	"context"

	jwt "github.com/golang-jwt/jwt/v5"
)

type ctxKeyType uint8

var (
	claimsKey        = ctxKeyType(1)
	expiredClaimsKey = ctxKeyType(2)
	tokenHashKey     = ctxKeyType(3)
)

func WithClaims(ctx context.Context, v jwt.MapClaims) context.Context {
	return context.WithValue(ctx, claimsKey, v)
}

func Claims(ctx context.Context) jwt.MapClaims {
	if v := ctx.Value(claimsKey); v != nil {
		return v.(jwt.MapClaims)
	}
	return nil
}

func WithExpiredClaims(ctx context.Context, v jwt.MapClaims) context.Context {
	return context.WithValue(ctx, expiredClaimsKey, v)
}

func ExpiredClaims(ctx context.Context) jwt.MapClaims {
	if v := ctx.Value(expiredClaimsKey); v != nil {
		return v.(jwt.MapClaims)
	}
	return nil
}

func WithTokenHash(ctx context.Context, v string) context.Context {
	return context.WithValue(ctx, tokenHashKey, v)
}

func TokenHash(ctx context.Context) string {
	if v := ctx.Value(tokenHashKey); v != nil {
		return v.(string)
	}
	return ""
}
