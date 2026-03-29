#!/usr/bin/env python3
"""NotTheNet - Fake Internet Simulator.

Thin entry point. The full GUI and CLI logic live in the `gui` package:

* `gui.widgets`  - constants, styling, reusable widgets
* `gui.dialogs`  - service configuration page classes
* `gui.views`    - dashboard layout and visual construction
* `gui.logic`    - service lifecycle and log management
* `gui.app`      - `NotTheNetApp` class and `main()`
"""

import os
import sys

APP_VERSION = "2026.03.29-2"

# Ensure the project root is in sys.path so that `config`, `service_manager`,
# `utils`, and `services` modules can be imported from the gui package.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gui.app import main  # noqa: E402

if __name__ == "__main__":
    main()
