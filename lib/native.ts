/**
 * Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

import bindings from 'bindings';

// Load the native GmSSL addon
const native = bindings('gmssl_native');
export default native;
