module github.com/example/app

go 1.21.0

toolchain go1.21.0

require github.com/gin-gonic/gin v1.9.0

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	golang.org/x/net v0.7.0 // indirect
	golang.org/x/text v0.3.7 // indirect
)

// A fork we build instead of the upstream module — the fork is what OSV should see.
replace github.com/upstream/lib => github.com/example/lib-fork v1.4.2

require github.com/upstream/lib v1.4.0

// Local code in this repo: not a scannable module at all.
replace github.com/example/internal v0.1.0 => ./internal

require github.com/example/internal v0.1.0

// A replace whose left side is never required has no effect (module reference).
replace github.com/never/required => github.com/some/other v9.9.9

exclude github.com/bad/pkg v1.0.0

// Block forms of the directives that must NEVER contribute modules: an excluded module is one
// the build deliberately avoids, and retract lines are about THIS module's own releases.
exclude (
	github.com/worse/pkg v2.0.0
	github.com/awful/pkg v3.0.0
)

retract v0.0.1

retract (
	v0.0.2
	[v0.1.0, v0.1.9]
)
