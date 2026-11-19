// SPDX-License-Identifier: Apache-2.0

package format

import (
	"errors"
	"regexp"
	"strings"
)

// PyPI is a read-through mirror of a Python package index (PEP 691): simple/<project>
// answers the index's page of a project, files/<project>/<sha256>/<file> each file it
// lists, kept once fetched. The project is named as PEP 503 normalises it.
type PyPI struct{}

var (
	pypiProject = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	sha256Hex   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func (PyPI) Name() string { return "pypi" }

func (PyPI) Route(rest []string) (Item, error) {
	switch {
	case len(rest) == 2 && rest[0] == "simple" && pypiProject.MatchString(rest[1]):
	case len(rest) == 4 && rest[0] == "files" && pypiProject.MatchString(rest[1]) && sha256Hex.MatchString(rest[2]) &&
		(strings.HasSuffix(rest[3], ".whl") || strings.HasSuffix(rest[3], ".tar.gz") || strings.HasSuffix(rest[3], ".zip")):
	default:
		return Item{}, errors.New("not simple/<project> nor files/<project>/<sha256>/<wheel or sdist>")
	}
	return Item{Key: strings.Join(rest, "/")}, nil
}

func init() { Register(PyPI{}) }
