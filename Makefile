#    Copyright 2025 Kubotal
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

APP_VERSION ?= v0.2.1-snapshot


BUILD_TS ?= $(shell date -u +%Y%m%d.%H%M%S)
# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)


##@ Build

.PHONY: build
build: ## Build kc binary with dependencies
	CGO_ENABLED=0 go build -ldflags '-X kc/global.Version=$(APP_VERSION) -X kc/global.BuildTs=$(BUILD_TS)' -o bin/kc main.go


##@ Release

# git tag X.X.X
# git push origin tag X.X.X
#
# export GITHUB_TOKEN=
# make release

# We reuse the same tag across runs. Force-move it to the current commit
# so goreleaser releases the just-pushed code (it releases the tagged
# commit, not branch HEAD).
move-tag: ## Set/move tag of current version
	git tag -f $(APP_VERSION)
	git push -f origin refs/tags/$(APP_VERSION)

.PHONY: release
release: move-tag ## Upload a release of kc cli client
	export APP_VERSION=$(APP_VERSION); export BUILD_TS=$(BUILD_TS);  goreleaser release --clean --skip validate


.PHONY: release-local
release-local:	move-tag	## Upload a release of kc cli client
	export APP_VERSION=$(APP_VERSION); export BUILD_TS=$(BUILD_TS);  goreleaser build --clean --skip validate
