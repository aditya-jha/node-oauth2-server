
/**
 * Module dependencies.
 */

var AbstractGrantType = require('./abstract-grant-type');
var InvalidArgumentError = require('../errors/invalid-argument-error');
var InvalidGrantError = require('../errors/invalid-grant-error');
var InvalidRequestError = require('../errors/invalid-request-error');
var ServerError = require('../errors/server-error');
var Promise = require('bluebird');
var is = require('../validator/is');
var util = require('util');

/**
 * Constructor.
 */

function OtpGrantType(options) {
  options = options || {};

  if (!options.model) {
    throw new InvalidArgumentError('Missing parameter: `model`');
  }

  if (!options.model.getUserFromPhone) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `getUserFromPhone()`');
  }

  if (!options.model.saveToken) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `saveToken()`');
  }

  AbstractGrantType.call(this, options);
}

/**
 * Inherit prototype.
 */

util.inherits(OtpGrantType, AbstractGrantType);

/**
 * Retrieve the user from the model using a username/password combination.
 *
 * @see https://tools.ietf.org/html/rfc6749#section-4.3.2
 */

OtpGrantType.prototype.handle = function(request, client) {
  if (!request) {
    throw new InvalidArgumentError('Missing parameter: `request`');
  }

  if (!client) {
    throw new InvalidArgumentError('Missing parameter: `client`');
  }

  var scope = this.getScope(request);

  return Promise.bind(this)
    .then(function() {
      return this.validateOtp(request);
    })
    .then(function(isOtpValid) {
      return this.verifyPhone(request);
    })
    .then(function(user) {
      return this.saveToken(user, client, scope);
    });
};

/**
 * Get user using a username/password combination.
 */

 OtpGrantType.prototype.upsertUser = function(request) {
   if (!request.body.phone) {
     throw new InvalidRequestError('Missing parameter: `phone`');
   }
  
   if (!is.uchar(request.body.phone)) {
     throw new InvalidRequestError('Invalid parameter: `phone`');
   }
  
   return Promise.try(this.model.upsertUser, [request.body.phone])
     .then(function(user) {
       if (!user) {
         throw new ServerError('User create/update Fail');
       }
       return user;
     });
 };

 OtpGrantType.prototype.verifyPhone = function(request) {
   if (!request.body.phone) {
     throw new InvalidRequestError('Missing parameter: `phone`');
   }
  
   if (!is.uchar(request.body.phone)) {
     throw new InvalidRequestError('Invalid parameter: `phone`');
   }
  
   return Promise.try(this.model.verifyPhone, [request.body.phone, request.body.user_id])
     .then(function(user) {
       if (!user) {
         throw new ServerError('User verifyPhone Fail');
       }
       return user;
     });
 };


OtpGrantType.prototype.validateOtp = function(request) {
  if (!request.body.phone) {
    throw new InvalidRequestError('Missing parameter: `phone`');
  }

  if (!request.body.otp) {
    throw new InvalidRequestError('Missing parameter: `otp`');
  }

  if (!is.uchar(request.body.phone)) {
    throw new InvalidRequestError('Invalid parameter: `phone`');
  }

  if (!is.uchar(request.body.otp)) {
    throw new InvalidRequestError('Invalid parameter: `otp`');
  }

  return Promise.try(this.model.validateOtp, [request.body.phone, request.body.otp])
    .then(function(isOtpValid) {
      if (!isOtpValid) {
        throw new InvalidGrantError('Invalid grant: user credentials are invalid');
      }

      return isOtpValid;
    });
};

/**
 * Save token.
 */

OtpGrantType.prototype.saveToken = function(user, client, scope) {
  var fns = [
    this.generateAccessToken(),
    this.generateRefreshToken(),
    this.getAccessTokenExpiresAt(),
    this.getRefreshTokenExpiresAt()
  ];

  return Promise.all(fns)
    .bind(this)
    .spread(function(accessToken, refreshToken, accessTokenExpiresAt, refreshTokenExpiresAt) {
      var token = {
        accessToken: accessToken,
        accessTokenExpiresAt: accessTokenExpiresAt,
        refreshToken: refreshToken,
        refreshTokenExpiresAt: refreshTokenExpiresAt,
        scope: scope
      };

      return this.model.saveToken(token, client, user);
    });
};

/**
 * Export constructor.
 */

module.exports = OtpGrantType;
