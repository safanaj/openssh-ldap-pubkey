#!/usr/bin/make -f
# -*- makefile -*-
#
# Copyright 2015-2020 Kouhei Maeda <mkouhei@palmtb.net>
# Copyright 2025 Marco Bardelli <marco@bardels.me>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#	  https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

VERSION ?= 0.3.2
COMPONENT = "openssh-ldap-pubkey"
FLAGS =
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
GO ?= go
LDFLAGS ?= -s -w


test:
	$(GO) build -v && $(GO) test -v && $(GO) vet

static:
	go build -a -tags netgo -gcflags "-e" \
		-ldflags "-s -w -extldflags=-static -X main.version=${VERSION}" \
		-o ${COMPONENT}_${GOOS}_${GOARCH}_${VERSION}
