var DKIM = require("./dkim");

const isDKIM = (v) => /^(DKIM-Signature|X-Google-DKIM-Signature)/.test(v);

/**
 * Verify a message signature
 * @memberOf DKIM
 * @param {Buffer} body
 * @param {Array} headers
 * @param {Function} callback
 */
function parseDkimVerifyResult(body, headers, callback) {
    var signature = null;
    // NOTE: result.status counts only if verified is not true
    var result = {
      verified: false,
      status: DKIM.NONE,
      error: null,
      signature: null,
      key: null,
    };
  
    try {
      if (!/^(DKIM-Signature|X-Google-DKIM-Signature)/i.test(headers[0])) {
        throw new Error("Missing DKIM-Signature");
      }
      signature = result.signature = DKIM.Signature.parse(
        headers[0].slice(headers[0].indexOf(":") + 1)
      );
    } catch (err) {
      result.error = err;
      result.error.code = result.status = DKIM.PERMFAIL;
      return callback(result.error, result);
    }
  
    // Truncate body to defined length
    body = signature.length != null ? body.slice(0, signature.length) : body;
    
    var processedHeader = DKIM.processHeader(
        headers,
        signature.headers,
        signature.canonical.split("/").shift()
    );

    result.processedHeader = processedHeader;
    result.verified = false;
    result.status = DKIM.NONE;

    callback(null, result);
}

/**
 * Verify a message's signatures
 * @memberOf DKIM
 * @param {Buffer} message
 * @param {Function} callback
 * @throws {Error} If input is not a buffer
 */
function parse(message, callback) {
  if (!Buffer.isBuffer(message)) {
    throw new Error("Message must be a Buffer");
  }

  var boundary = message.indexOf("\r\n\r\n");
  if (boundary === -1) {
    return callback(new Error("No header boundary found"));
  }

  var header = message.toString("utf8", 0, boundary);
  var body = message.slice(boundary + 4);

  var results = [];
  var signatures = [];

  header.split(/\r\n(?=[^\x20\x09]|$)/g).forEach(function (h, i, headers) {
    // ISSUE: executing line below, may result in including a different 'DKIM-Signature' header
    // signatures.push( headers.slice( i ) )
    // FIX: after slicing, remove any included 'DKIM-Signature' header that differ from "oneHeader"
    if (isDKIM(h)) {
      // remove DKIM headers
      const sigHeaders = headers.filter((v) => !isDKIM(v));
      // add one DKIM header
      sigHeaders.unshift(h);

      signatures.push(sigHeaders);
    }
  });

  function _parse() {
    var headers = signatures.pop();
    if (headers == null) {
      return callback(null, results);
    }
    
    parseDkimVerifyResult(body, headers, function (error, result) {
      if (error) return callback(error, results);
      results.push(result);
      _parse();
    });
  }

  _parse();
}

/**
 * Filter out signature headers other than the specified `signatureHeader`
 * @param {Array<String>} headers - list of headers to filter
 * @param {String} signatureHeader - signature header to keep
 * @return {Array<String>} filtered headers
 */
parse.filterSignatureHeaders = function filterSignatureHeaders(
  headers,
  signatureHeader
) {
  return headers.filter(function (header) {
    return (
      header === signatureHeader ||
      !/^(DKIM-Signature|X-Google-DKIM-Signature)/i.test(header)
    );
  });
};

module.exports = parse;
