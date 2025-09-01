# Introduction to Open1722 Contribution Process

There are two main methods to propose changes or extensions to Open1722:

- If you have an idea or a question you can create an [issue](hhttps://github.com/COVESA/Open1722/issues) in GitHub.
- If you already have prepared changes or extension that you think would be interesting for COVESA to include in Open1722
  then you can create a [Pull Request (PR)](https://github.com/COVESA/Open1722/pulls).

All contributions must follow the [COVESA contribution guidelines](https://covesa.global/contribute).

## Creating a Pull Request towards Open1722

This is the typical workflow for preparing a pull request. A GitHub account is required.

1. Create a personal or company fork of the [Open1722 repository](https://github.com/COVESA/Open1722)
2. Clone the forked repository into your local development environment.
3. Set up your local development environment, see [README.md](README.md) for some guidance.
4. Create a local branch based on the Open1722 main branch to use for the proposed changes.
5. Introduce the wanted changes or extensions in your local development environment, 6. Create a commit and upload to your own fork.
7. In the GitHub UI, create a Pull Request from your fork to the main branch of [the Open1722 repository](https://github.com/COVESA/Open1722).
8. Validate that automatic build checks for the PR succeed.


## Guidelines and Recommendations

This section includes general guidelines and recommendations for anyone interested in contributing to OPen1722.

### All contributions must follow COVESA contribution guidelines

COVESA has defined [contribution guidelines](https://covesa.global/contribute).

Every contribution (commit) must carry the following sign-off line with your real name and email address:

`Signed-off-by: Firstname Lastname <you@example.com>`

By supplying this sign-off line, you indicate your acceptance of the COVESA Certificate of Origin.

If using git command line you can add a sign-off by using the `-s` argument when creating a commit.

For code files it is requested that a copyright and license statement is added as file header.

This is the standard copyright header template for most Open1722 files

```
/*
 * Copyright (c) 2024, COVESA
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of COVESA nor the names of its contributors may be
 *      used to endorse or promote products derived from this software without
 *      specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
```

Where {year} is the year the file was originally created. No need to update or append new years or a range of years later.

### Additional licenses

Not that _all_ Open1722 code is always available under BSD-3-Clause license. For some components - at the choice of the user - other _addtional_ licenses may apply. This is done to enable integration of Open1722 into ecosystems demanding other licenses.  

As an example for components related to Linux Kernel integration you might see

```
SPDX-License-Identifier: BSD-3-Clause or GPL-2.0
```

When modifying a code file with such an extended license claim, your DCO confirms you are willing and able to release your provided contribution under either license mentioned in the SPDX-License-Identifier.
