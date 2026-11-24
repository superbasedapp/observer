#!/usr/bin/env node
// superbased: the short npm name for @superbased/observer. It installs the
// same release as a dependency and hands over to its launcher, which finds
// the platform binary and forwards arguments, stdio and the exit code.
'use strict';

require('@superbased/observer/bin/observer.js');
