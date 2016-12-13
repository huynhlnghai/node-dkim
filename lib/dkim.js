/** @type {Object} */
var DKIM = module.exports

/** @type {String} */
DKIM.NONE = 'NONE'
/** @type {String} */
DKIM.OK = 'OK'
/** @type {String} */
DKIM.TEMPFAIL = 'TEMPFAIL'
/** @type {String} */
DKIM.PERMFAIL = 'PERMFAIL'

/**
 * DKIM Signature
 * @constructor
 * @see [dkim-signature](https://github.com/jhermsmeier/node-dkim-signature)
 */
DKIM.Signature = require( 'dkim-signature' )

/**
 * DKIM Key
 * @constructor
 * @see [dkim-key](https://github.com/jhermsmeier/node-dkim-key)
 */
DKIM.Key = require( 'dkim-key' )

DKIM.getKey = require( './get-key' )