./: {*/ -build/ -certifiable-build/ -include/ -.github/ -docs/} \
  doc{README.md} \
  legal{LICENSE} \
  manifest

./: src/ tests/

import src = src/
import tests = tests/

# Don't install tests.
#
tests/: install = false
