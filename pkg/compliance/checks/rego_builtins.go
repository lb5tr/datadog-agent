// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package checks

import (
	"errors"
	"strconv"

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

const helpers = `
package datadog

docker_container_resource_id(c) = id {
	id := sprintf("%s_%s", [input.context.hostname, cast_string(c.id)])
}

docker_image_resource_id(img) = id {
	hash := split(cast_string(img.id), ":")[1]
	id := sprintf("%s_%s", [input.context.hostname, hash])
}

docker_daemon_resource_id = id {
	id := sprintf("%s_daemon", [input.context.hostname])
}

passed_finding(resource_type, resource_id, event_data) = f {
	f := raw_finding(true, resource_type, resource_id, event_data)
}

failing_finding(resource_type, resource_id, event_data) = f {
	f := raw_finding(false, resource_type, resource_id, event_data)
}

docker_container_data(c) = d {
	d := {
		"container.id": c.id,
		"container.image": c.image,
		"container.name": c.name,
	}
}

docker_image_data(img) = d {
	d := {
		"image.id": img.id,
		"image.tags": img.tags,
	}
}

process_data(p) = d {
	d := {
		"process.name": p.name,
		"process.exe": p.exe,
		"process.cmdLine": p.cmdLine,
	}
}

file_data(file) = d {
	d := {
		"file.group": file.group,
		"file.path": file.path,
		"file.permissions": file.permissions,
		"file.user": file.user,
	}
}

group_data(group) = d {
	d := {
		"group.id": group.id,
		"group.name": group.name,
		"group.users": group.users,
	}
}

audit_data(audit) = d {
	d := {
		"audit.enabled": audit.enabled,
		"audit.path": audit.path,
		"audit.permissions": audit.permissions,
	}
}
`

var regoBuiltins = []func(*rego.Rego){
	octalLiteralFunc,
	rawFinding,
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

var rawFinding = rego.Function4(
	&rego.Function{
		Name: "raw_finding",
		Decl: types.NewFunction(types.Args(types.B, types.S, types.S, types.A), types.A),
	},
	func(_ rego.BuiltinContext, status, resType, resID, data *ast.Term) (*ast.Term, error) {
		terms := [][2]*ast.Term{
			{
				ast.StringTerm(ResourceIDFindingField),
				resID,
			},
			{
				ast.StringTerm(ResourceTypeFindingField),
				resType,
			},
			{
				ast.StringTerm(ResourceDataFindingField),
				data,
			},
			{
				ast.StringTerm(ResourceStatusFindingField),
				status,
			},
		}

		return ast.ObjectTerm(terms...), nil
	},
)