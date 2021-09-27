// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package checks

import (
	"errors"
	"strconv"

	_ "embed"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
)

const (
	// ResourceIDFindingField represents the resource id field name in finding document
	ResourceIDFindingField = "resource_id"
	// ResourceTypeFindingField represents the resource type field name in finding document
	ResourceTypeFindingField = "resource_type"
	// ResourceStatusFindingField represents the resource status field name in finding document
	ResourceStatusFindingField = "status"
	// ResourceDataFindingField represents the resource data field name in finding document
	ResourceDataFindingField = "data"
)

//go:embed rego_helpers/datadog.rego
var helpers string

var regoBuiltins = []func(*rego.Rego){
	octalLiteralFunc,
}

var octalLiteralFunc = rego.Function1(
	&rego.Function{
		Name: "parse_octal",
		Decl: types.NewFunction(types.Args(types.S), types.N),
	},
	func(_ rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
		str, ok := a.Value.(ast.String)
		if !ok {
			return nil, errors.New("failed to parse octal literal")
		}

		value, err := strconv.ParseInt(string(str), 8, 0)
		if err != nil {
			return nil, err
		}

		return ast.IntNumberTerm(int(value)), err
	},
)
