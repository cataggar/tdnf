#!/bin/sh

COVERITY_BIN=/coverity/bin/
export PATH=${COVERITY_BIN}:${PATH}

COVERITY_DIR=build-coverity
rm -rf ${COVERITY_DIR}
mkdir -p ${COVERITY_DIR}

# Coverity's cov-configure needs a "compiler" to probe. Wrap `zig cc` so it
# looks like a regular clang to Coverity.
ZIG_CC_WRAPPER=${COVERITY_DIR}/cc-zig
cat > "${ZIG_CC_WRAPPER}" <<'EOF'
#!/bin/sh
exec zig cc "$@"
EOF
chmod +x "${ZIG_CC_WRAPPER}"

COV_CONFIG=${COVERITY_DIR}/coverity-config.xml
COV_DIR=${COVERITY_DIR}/coverity-intermediate

cov-configure --config ${COV_CONFIG} --compiler "$(realpath ${ZIG_CC_WRAPPER})" --comptype clangcc --template

# Force the build to use our wrapper. Coverity will instrument the
# invocations and record the build graph.
CC="$(realpath ${ZIG_CC_WRAPPER})" cov-build --dir ${COV_DIR} --config ${COV_CONFIG} zig build

cov-analyze --dir ${COV_DIR} --config ${COV_CONFIG} --all

mkdir -p ${COVERITY_DIR}/html
cov-format-errors --dir ${COV_DIR} --html-output ${COVERITY_DIR}/html

