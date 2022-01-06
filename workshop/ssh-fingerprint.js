/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
;(function (exports) {
'use strict';

if (!exports.Enc) { exports.Enc = {}; }
if (!exports.SSH) { exports.SSH = {}; }

var Enc = exports.Enc;
var SSH = exports.SSH;

SSH.fingerprint = function (opts) {
  var ssh;
  if (opts.bytes) {
    ssh = opts;
  } else {
    ssh = SSH.parseBlock(opts.pub);
  }
  ssh = SSH.parseElements(ssh);

  // for browser compat
  return window.crypto.subtle.digest('SHA-256', ssh.bytes).then(function (digest) {
    digest = new Uint8Array(digest);
    // 2048 SHA256:yCB62vBVsOwqksgYwy/WDbaMF2PhPijAwcrlzmrxfko rsa@localhost (RSA)
    // 256 SHA256:wcH95nkL7ZkeRURHpLuoThIBEIIKkYgf9etD18PIx40 P-256@localhost (ECDSA)
    ssh = SSH.parseKeyType(ssh);
    return {
      type: 'sha256'
    , digest: digest
    , fingerprint: 'SHA256:' + Enc.bufToBase64(digest).replace(/=+$/g, '')
    , size: ssh.size
    , comment: ssh.comment
    , kty: ssh.kty
    };
  });
};

SSH.parseBlock = function (ssh) {
  ssh = ssh.split(/\s+/g);

  return {
    type: ssh[0]
  , bytes: Enc.base64ToBuf(ssh[1])
  , comment: ssh[2]
  };
};

SSH.parseElements = function (ssh) {
  var buf = ssh.bytes;
  var fulllen = buf.byteLength || buf.length;
  var offset = (buf.byteOffset || 0);
  var i = 0;
  var index = 0;
  // using dataview to be browser-compatible (I do want _some_ code reuse)
  var dv = new DataView(buf.buffer.slice(offset, offset + fulllen));
  var els = [];
  var el;
  var len;

  while (index < fulllen) {
    i += 1;
    if (i > 15) { throw new Error("15+ elements, probably not a public ssh key"); }
    len = dv.getUint32(index, false);
    index += 4;
    el = buf.slice(index, index + len);
    // remove BigUInt '00' prefix
    if (0x00 === el[0]) {
      el = el.slice(1);
    }
    els.push(el);
    index += len;
  }
  if (fulllen !== index) {
    throw new Error("invalid ssh public key length \n" + els.map(function (b) {
      return Enc.bufToHex(b);
    }).join('\n'));
  }

  ssh.elements = els;
  return ssh;
};

SSH.parseKeyType = function (ssh) {
  var els = ssh.elements;
  var typ = Enc.bufToBin(els[0]);

  // RSA keys are all the same
  if (SSH.types.rsa === typ) {
    ssh.kty = 'RSA';
    ssh.size = (ssh.elements[2].byteLength || ssh.lements[2].length);
    return ssh;
  }

  // EC keys are each different
  if (SSH.types.p256 === typ) {
    ssh.kty = 'EC';
    ssh.size = 32;
  } else if (SSH.types.p384 === typ) {
    ssh.kty = 'EC';
    ssh.size = 48;
  } else {
    throw new Error("Unsupported ssh public key type: "
      + Enc.bufToBin(els[0]));
  }

  return ssh;
};

SSH.types = {
  // 19 '00000013'
  // e c d s a - s h a 2 - n i s t p 2 5 6
  // 65636473612d736861322d6e69737470323536
  // 6e69737470323536
  p256: 'ecdsa-sha2-nistp256'

  // 19 '00000013'
  // e c d s a - s h a 2 - n i s t p 3 8 4
  // 65636473612d736861322d6e69737470333834
  // 6e69737470323536
, p384: 'ecdsa-sha2-nistp384'

  // 7 '00000007'
  // s s h - r s a
  // 7373682d727361
, rsa: 'ssh-rsa'
};

Enc.base64ToBuf = function (b64) {
  return Enc.binToBuf(atob(b64));
};

Enc.binToBuf = function (bin) {
  var arr = bin.split('').map(function (ch) {
    return ch.charCodeAt(0);
  });
  return 'undefined' !== typeof Uint8Array ? new Uint8Array(arr) : arr;
};

Enc.bufToBase64 = function (u8) {
  var bin = '';
  u8.forEach(function (i) {
    bin += String.fromCharCode(i);
  });
  return btoa(bin);
};

Enc.bufToBin = function (buf) {
  var bin = '';
  // cannot use .map() because Uint8Array would return only 0s
  buf.forEach(function (ch) {
    bin += String.fromCharCode(ch);
  });
  return bin;
};

}('undefined' !== typeof window ? window : module.exports));
