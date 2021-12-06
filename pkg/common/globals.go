// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package common

import "flag"

var CNITypeInUse CNIType

var (
	DataInterface = flag.String("data-interface", "", "")
)
