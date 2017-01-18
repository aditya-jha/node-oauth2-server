
/**
 * Module dependencies.
 */

var _ = require('lodash');
var OAuthError = require('./oauth-error');
var util = require('util');

/**
 * Constructor.
 *
 * "The authorization server encountered an unexpected condition that prevented it from fulfilling the request."
 *
 * @see https://tools.ietf.org/html/rfc6749#section-4.1.2.1
 */

function ServerError(message, properties) {
  properties = _.assign({
    name: 'server_error', 
    code: message.statusCode || 503,
  }, properties);

  OAuthError.call(this, message, properties);
}

/**
 * Inherit prototype.
 */

util.inherits(ServerError, OAuthError);

/**
 * Export constructor.
 */

module.exports = ServerError;
