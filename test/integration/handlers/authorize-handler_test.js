
/**
 * Module dependencies.
 */

var AccessDeniedError = require('../../../lib/errors/access-denied-error');
var AuthenticateHandler = require('../../../lib/handlers/authenticate-handler');
var AuthorizeHandler = require('../../../lib/handlers/authorize-handler');
var CodeResponseType = require('../../../lib/response-types/code-response-type');
var InvalidArgumentError = require('../../../lib/errors/invalid-argument-error');
var InvalidClientError = require('../../../lib/errors/invalid-client-error');
var InvalidRequestError = require('../../../lib/errors/invalid-request-error');
var Promise = require('bluebird');
var Request = require('../../../lib/request');
var Response = require('../../../lib/response');
var UnauthorizedClientError = require('../../../lib/errors/unauthorized-client-error');
var should = require('should');
var url = require('url');

/**
 * Test `AuthorizeHandler` integration.
 */

describe('AuthorizeHandler integration', function() {
  describe('constructor()', function() {
    it('should throw an error if `options.authorizationCodeLifetime` is missing', function() {
      try {
        new AuthorizeHandler();

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal('Missing parameter: `authorizationCodeLifetime`');
      }
    });

    it('should throw an error if `options.model` is missing', function() {
      try {
        new AuthorizeHandler({ authorizationCodeLifetime: 120 });

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal('Missing parameter: `model`');
      }
    });

    it('should throw an error if the model does not implement `getClient()`', function() {
      try {
        new AuthorizeHandler({ authorizationCodeLifetime: 120, model: {} });

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal('Invalid argument: model does not implement `getClient()`');
      }
    });

    it('should throw an error if the model does not implement `saveAuthorizationCode()`', function() {
      try {
        new AuthorizeHandler({ authorizationCodeLifetime: 120, model: { getClient: function() {} } });

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal('Invalid argument: model does not implement `saveAuthorizationCode()`');
      }
    });

    it('should throw an error if the model does not implement `getAccessToken()`', function() {
      var model = {
        getClient: function() {},
        saveAuthorizationCode: function() {}
      };

      try {
        new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal('Invalid argument: model does not implement `getAccessToken()`');
      }
    });

    it('should set the `authorizationCodeLifetime`', function() {
      var model = {
        getAccessToken: function() {},
        getClient: function() {},
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });

      handler.authorizationCodeLifetime.should.equal(120);
    });

    it('should set the `authenticateHandler`', function() {
      var model = {
        getAccessToken: function() {},
        getClient: function() {},
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });

      handler.authenticateHandler.should.be.an.instanceOf(AuthenticateHandler);
    });

    it('should set the `model`', function() {
      var model = {
        getAccessToken: function() {},
        getClient: function() {},
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });

      handler.model.should.equal(model);
    });
  });

  describe('handle()', function() {
    it('should throw an error if `request` is missing', function() {
      var model = {
        getAccessToken: function() {},
        getClient: function() {},
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });

      try {
        handler.handle();

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal('Invalid argument: `request` must be an instance of Request');
      }
    });

    it('should throw an error if `response` is missing', function() {
      var model = {
        getAccessToken: function() {},
        getClient: function() {},
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
      var request = new Request({ body: {}, headers: {}, method: {}, query: {} });

      try {
        handler.handle(request);

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal('Invalid argument: `response` must be an instance of Response');
      }
    });

    it('should throw an error if `allowed` is `false`', function() {
      var model = {
        getAccessToken: function() {},
        getClient: function() {},
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
      var request = new Request({ body: {}, headers: {}, method: {}, query: { allowed: 'false' } });
      var response = new Response({ body: {}, headers: {} });

      return handler.handle(request, response)
        .then(should.fail)
        .catch(function(e) {
          e.should.be.an.instanceOf(AccessDeniedError);
          e.message.should.equal('Access denied: user denied access to application');
        });
    });

    it('should redirect to an error response if a non-oauth error is thrown', function() {
      var model = {
        getAccessToken: function() {
          return { user: {} };
        },
        getClient: function() {
          return { grants: ['authorization_code'], redirectUri: 'http://example.com/cb' };
        },
        saveAuthorizationCode: function() {
          throw new Error('Unhandled exception');
        }
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
      var request = new Request({
        body: {
          client_id: 12345,
          response_type: 'code'
        },
        headers: {
          'Authorization': 'Bearer foo'
        },
        method: {},
        query: {
          state: 'foobar'
        }
      });
      var response = new Response({ body: {}, headers: {} });

      return handler.handle(request, response)
        .then(should.fail)
        .catch(function() {
          response.get('location').should.equal('http://example.com/cb?error=server_error&error_description=Unhandled%20exception&state=foobar');
        });
    });

    it('should redirect to an error response if an oauth error is thrown', function() {
      var model = {
        getAccessToken: function() {
          return { user: {} };
        },
        getClient: function() {
          return { grants: ['authorization_code'], redirectUri: 'http://example.com/cb' };
        },
        saveAuthorizationCode: function() {
          throw new AccessDeniedError('Cannot request this auth code');
        }
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
      var request = new Request({
        body: {
          client_id: 12345,
          response_type: 'code'
        },
        headers: {
          'Authorization': 'Bearer foo'
        },
        method: {},
        query: {
          state: 'foobar'
        }
      });
      var response = new Response({ body: {}, headers: {} });

      return handler.handle(request, response)
        .then(should.fail)
        .catch(function() {
          response.get('location').should.equal('http://example.com/cb?error=access_denied&error_description=Cannot%20request%20this%20auth%20code&state=foobar');
        });
    });

    it('should redirect to a successful response with `code` and `state` if successful', function() {
      var client = { grants: ['authorization_code'], redirectUri: 'http://example.com/cb' };
      var model = {
        getAccessToken: function() {
          return { client: client, user: {} };
        },
        getClient: function() {
          return client;
        },
        saveAuthorizationCode: function() {
          return { authorizationCode: 12345, client: client };
        }
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
      var request = new Request({
        body: {
          client_id: 12345,
          response_type: 'code'
        },
        headers: {
          'Authorization': 'Bearer foo'
        },
        method: {},
        query: {
          state: 'foobar'
        }
      });
      var response = new Response({ body: {}, headers: {} });

      return handler.handle(request, response)
        .then(function() {
          response.get('location').should.equal('http://example.com/cb?code=12345&state=foobar');
        })
        .catch(should.fail);
    });

    it('should return the `code` if successful', function() {
      var client = { grants: ['authorization_code'], redirectUri: 'http://example.com/cb' };
      var model = {
        getAccessToken: function() {
          return { client: client, user: {} };
        },
        getClient: function() {
          return client;
        },
        saveAuthorizationCode: function() {
          return { authorizationCode: 12345, client: client };
        }
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
      var request = new Request({
        body: {
          client_id: 12345,
          response_type: 'code'
        },
        headers: {
          'Authorization': 'Bearer foo'
        },
        method: {},
        query: {
          state: 'foobar'
        }
      });
      var response = new Response({ body: {}, headers: {} });

      return handler.handle(request, response)
        .then(function(data) {
          data.should.eql({
            authorizationCode: 12345,
            client: client
          });
        })
        .catch(should.fail);
    });
  });

  describe('generateAuthorizationCode()', function() {
    it('should return an auth code', function() {
      var model = {
        getAccessToken: function() {},
        getClient: function() {},
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });

      return handler.generateAuthorizationCode()
        .then(function(data) {
          data.should.be.a.sha1;
        })
        .catch(should.fail);
    });

    it('should support promises', function() {
      var model = {
        generateAuthorizationCode: function() {
          return Promise.resolve({});
        },
        getAccessToken: function() {},
        getClient: function() {},
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });

      handler.generateAuthorizationCode().should.be.an.instanceOf(Promise);
    });

    it('should support non-promises', function() {
      var model = {
        generateAuthorizationCode: function() {
          return {};
        },
        getAccessToken: function() {},
        getClient: function() {},
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });

      handler.generateAuthorizationCode().should.be.an.instanceOf(Promise);
    });
  });

  describe('getAuthorizationCodeLifetime()', function() {
    it('should return a date', function() {
      var model = {
        getAccessToken: function() {},
        getClient: function() {},
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });

      handler.getAuthorizationCodeLifetime().should.be.an.instanceOf(Date);
    });
  });

  describe('getClient()', function() {
    it('should throw an error if `client_id` is missing', function() {
      var model = {
        getAccessToken: function() {},
        getClient: function() {},
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
      var request = new Request({ body: { response_type: 'code' }, headers: {}, method: {}, query: {} });

      try {
        handler.getClient(request);

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidRequestError);
        e.message.should.equal('Missing parameter: `client_id`');
      }
    });

    it('should throw an error if `client_id` is invalid', function() {
      var model = {
        getAccessToken: function() {},
        getClient: function() {},
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
      var request = new Request({ body: { client_id: 'øå€£‰', response_type: 'code' }, headers: {}, method: {}, query: {} });

      try {
        handler.getClient(request);

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidRequestError);
        e.message.should.equal('Invalid parameter: `client_id`');
      }
    });

    it('should throw an error if `client.redirectUri` is invalid', function() {
      var model = {
        getAccessToken: function() {},
        getClient: function() {},
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
      var request = new Request({ body: { client_id: 12345, response_type: 'code', redirect_uri: 'foobar' }, headers: {}, method: {}, query: {} });

      try {
        handler.getClient(request);

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidRequestError);
        e.message.should.equal('Invalid request: `redirect_uri` is not a valid URI');
      }
    });

    it('should throw an error if `client` is missing', function() {
      var model = {
        getAccessToken: function() {},
        getClient: function() {},
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
      var request = new Request({ body: { client_id: 12345, response_type: 'code' }, headers: {}, method: {}, query: {} });

      return handler.getClient(request)
        .then(should.fail)
        .catch(function(e) {
          e.should.be.an.instanceOf(InvalidClientError);
          e.message.should.equal('Invalid client: client credentials are invalid');
        });
    });

    it('should throw an error if `client` is missing', function() {
      var model = {
        getAccessToken: function() {},
        getClient: function() {},
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
      var request = new Request({ body: { client_id: 12345, response_type: 'code' }, headers: {}, method: {}, query: {} });

      return handler.getClient(request)
        .then(should.fail)
        .catch(function(e) {
          e.should.be.an.instanceOf(InvalidClientError);
          e.message.should.equal('Invalid client: client credentials are invalid');
        });
    });

    it('should throw an error if `client.grants` is missing', function() {
      var model = {
        getAccessToken: function() {},
        getClient: function() {
          return {};
        },
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
      var request = new Request({ body: { client_id: 12345, response_type: 'code' }, headers: {}, method: {}, query: {} });

      return handler.getClient(request)
        .then(should.fail)
        .catch(function(e) {
          e.should.be.an.instanceOf(InvalidClientError);
          e.message.should.equal('Invalid client: missing client `grants`');
        });
    });

    it('should throw an error if `client` is unauthorized', function() {
      var model = {
        getAccessToken: function() {},
        getClient: function() {
          return { grants: [] };
        },
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
      var request = new Request({ body: { client_id: 12345, response_type: 'code' }, headers: {}, method: {}, query: {} });

      return handler.getClient(request)
        .then(should.fail)
        .catch(function(e) {
          e.should.be.an.instanceOf(UnauthorizedClientError);
          e.message.should.equal('Unauthorized client: `grant_type` is invalid');
        });
    });

    it('should throw an error if `client.redirectUri` is missing', function() {
      var model = {
        getAccessToken: function() {},
        getClient: function() { return { grants: ['authorization_code'] }; },
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
      var request = new Request({ body: { client_id: 12345, response_type: 'code' }, headers: {}, method: {}, query: {} });

      return handler.getClient(request)
        .then(should.fail)
        .catch(function(e) {
          e.should.be.an.instanceOf(InvalidClientError);
          e.message.should.equal('Invalid client: missing client `redirectUri`');
        });
    });

    it('should throw an error if `client.redirectUri` is not equal to `redirectUri`', function() {
      var model = {
        getAccessToken: function() {},
        getClient: function() {
          return { grants: ['authorization_code'], redirectUri: 'https://example.com' };
        },
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
      var request = new Request({ body: { client_id: 12345, response_type: 'code', redirect_uri: 'https://foobar.com' }, headers: {}, method: {}, query: {} });

      return handler.getClient(request)
        .then(should.fail)
        .catch(function(e) {
          e.should.be.an.instanceOf(InvalidClientError);
          e.message.should.equal('Invalid client: `redirect_uri` does not match client value');
        });
    });

    it('should support promises', function() {
      var model = {
        getAccessToken: function() {},
        getClient: function() {
          return Promise.resolve({ grants: ['authorization_code'], redirectUri: 'http://example.com/cb' });
        },
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
      var request = new Request({
        body: { client_id: 12345 },
        headers: {},
        method: {},
        query: {}
      });

      handler.getClient(request).should.be.an.instanceOf(Promise);
    });

    it('should support non-promises', function() {
      var model = {
        getAccessToken: function() {},
        getClient: function() {
          return { grants: ['authorization_code'], redirectUri: 'http://example.com/cb' };
        },
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
      var request = new Request({
        body: { client_id: 12345 },
        headers: {},
        method: {},
        query: {}
      });

      handler.getClient(request).should.be.an.instanceOf(Promise);
    });

    describe('with `client_id` in the request body', function() {
      it('should return a client', function() {
        var client = { grants: ['authorization_code'], redirectUri: 'http://example.com/cb' };
        var model = {
          getAccessToken: function() {},
          getClient: function() {
            return client;
          },
          saveAuthorizationCode: function() {}
        };
        var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
        var request = new Request({ body: { client_id: 12345, response_type: 'code' }, headers: {}, method: {}, query: {} });

        return handler.getClient(request)
          .then(function(data) {
            data.should.equal(client);
          })
          .catch(should.fail);
      });
    });

    describe('with `client_id` in the request query', function() {
      it('should return a client', function() {
        var client = { grants: ['authorization_code'], redirectUri: 'http://example.com/cb' };
        var model = {
          getAccessToken: function() {},
          getClient: function() {
            return client;
          },
          saveAuthorizationCode: function() {}
        };
        var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
        var request = new Request({ body: { response_type: 'code' }, headers: {}, method: {}, query: { client_id: 12345 } });

        return handler.getClient(request)
          .then(function(data) {
            data.should.equal(client);
          })
          .catch(should.fail);
      });
    });
  });

  describe('getScope()', function() {
    it('should throw an error if `scope` is invalid', function() {
      var model = {
        getAccessToken: function() {},
        getClient: function() {},
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
      var request = new Request({ body: { scope: 'øå€£‰' }, headers: {}, method: {}, query: {} });

      try {
        handler.getScope(request);

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal('Invalid parameter: `scope`');
      }
    });

    it('should return the scope', function() {
      var model = {
        getAccessToken: function() {},
        getClient: function() {},
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
      var request = new Request({ body: { scope: 'foo' }, headers: {}, method: {}, query: {} });

      handler.getScope(request).should.equal('foo');
    });
  });

  describe('getState()', function() {
    it('should throw an error if `state` is missing', function() {
      var model = {
        getAccessToken: function() {},
        getClient: function() {},
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
      var request = new Request({ body: {}, headers: {}, method: {}, query: {} });

      try {
        handler.getState(request);

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidRequestError);
        e.message.should.equal('Missing parameter: `state`');
      }
    });

    it('should throw an error if `state` is invalid', function() {
      var model = {
        getAccessToken: function() {},
        getClient: function() {},
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
      var request = new Request({ body: {}, headers: {}, method: {}, query: { state: 'øå€£‰' } });

      try {
        handler.getState(request);

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidRequestError);
        e.message.should.equal('Invalid parameter: `state`');
      }
    });

    describe('with `state` in the request body', function() {
      it('should return the state', function() {
        var model = {
          getAccessToken: function() {},
          getClient: function() {},
          saveAuthorizationCode: function() {}
        };
        var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
        var request = new Request({ body: { state: 'foobar' }, headers: {}, method: {}, query: {} });

        handler.getState(request).should.equal('foobar');
      });
    });

    describe('with `state` in the request query', function() {
      it('should return the state', function() {
        var model = {
          getAccessToken: function() {},
          getClient: function() {},
          saveAuthorizationCode: function() {}
        };
        var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
        var request = new Request({ body: {}, headers: {}, method: {}, query: { state: 'foobar' } });

        handler.getState(request).should.equal('foobar');
      });
    });
  });

  describe('getUser()', function() {
    it('should return a user', function() {
      var user = {};
      var model = {
        getAccessToken: function() {
          return { user: user };
        },
        getClient: function() {},
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
      var request = new Request({ body: {}, headers: { 'Authorization': 'Bearer foo' }, method: {}, query: {} });
      var response = new Response({ body: {}, headers: {} });

      return handler.getUser(request, response)
        .then(function(data) {
          data.should.equal(user);
        })
        .catch(should.fail);
    });
  });

  describe('saveAuthorizationCode()', function() {
    it('should return an auth code', function() {
      var authorizationCode = {};
      var model = {
        getAccessToken: function() {},
        getClient: function() {},
        saveAuthorizationCode: function() {
          return authorizationCode;
        }
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });

      return handler.saveAuthorizationCode('foo', 'bar', 'biz', 'baz')
        .then(function(data) {
          data.should.equal(authorizationCode);
        })
        .catch(should.fail);
    });

    it('should support promises when calling `model.saveAuthorizationCode()`', function() {
      var model = {
        getAccessToken: function() {},
        getClient: function() {},
        saveAuthorizationCode: function() {
          return Promise.resolve({});
        }
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });

      handler.saveAuthorizationCode('foo', 'bar', 'biz', 'baz').should.be.an.instanceOf(Promise);
    });

    it('should support non-promises when calling `model.saveAuthorizationCode()`', function() {
      var model = {
        getAccessToken: function() {},
        getClient: function() {},
        saveAuthorizationCode: function() {
          return {};
        }
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });

      handler.saveAuthorizationCode('foo', 'bar', 'biz', 'baz').should.be.an.instanceOf(Promise);
    });
  });

  describe('getResponseType()', function() {
    it('should throw an error if `response_type` is missing', function() {
      var model = {
        getAccessToken: function() {},
        getClient: function() {},
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
      var request = new Request({ body: {}, headers: {}, method: {}, query: {} });

      try {
        handler.getResponseType(request);

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidRequestError);
        e.message.should.equal('Missing parameter: `response_type`');
      }
    });

    it('should throw an error if `response_type` is not `code`', function() {
      var model = {
        getAccessToken: function() {},
        getClient: function() {},
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
      var request = new Request({ body: { response_type: 'foobar' }, headers: {}, method: {}, query: {} });

      try {
        handler.getResponseType(request);

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidRequestError);
        e.message.should.equal('Invalid parameter: `response_type`');
      }
    });

    describe('with `response_type` in the request body', function() {
      it('should return a response type', function() {
        var model = {
        getAccessToken: function() {},
        getClient: function() {},
        saveAuthorizationCode: function() {}
      };
        var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
        var request = new Request({ body: { response_type: 'code' }, headers: {}, method: {}, query: {} });
        var responseType = handler.getResponseType(request, { authorizationCode: 123 });

        responseType.should.be.an.instanceOf(CodeResponseType);
      });
    });

    describe('with `response_type` in the request query', function() {
      it('should return a response type', function() {
        var model = {
        getAccessToken: function() {},
        getClient: function() {},
        saveAuthorizationCode: function() {}
      };
        var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
        var request = new Request({ body: {}, headers: {}, method: {}, query: { response_type: 'code' } });
        var responseType = handler.getResponseType(request, { authorizationCode: 123 });

        responseType.should.be.an.instanceOf(CodeResponseType);
      });
    });
  });

  describe('buildSuccessRedirectUri()', function() {
    it('should return a redirect uri', function() {
      var model = {
        getAccessToken: function() {},
        getClient: function() {},
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
      var responseType = new CodeResponseType(12345);
      var redirectUri = handler.buildSuccessRedirectUri('http://example.com/cb', responseType);

      url.format(redirectUri).should.equal('http://example.com/cb?code=12345');
    });
  });

  describe('buildErrorRedirectUri()', function() {
    it('should set `error_description` if available', function() {
      var error = new InvalidClientError('foo bar');
      var model = {
        getAccessToken: function() {},
        getClient: function() {},
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
      var redirectUri = handler.buildErrorRedirectUri('http://example.com/cb', error);

      url.format(redirectUri).should.equal('http://example.com/cb?error=invalid_client&error_description=foo%20bar');
    });

    it('should return a redirect uri', function() {
      var error = new InvalidClientError();
      var model = {
        getAccessToken: function() {},
        getClient: function() {},
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
      var redirectUri = handler.buildErrorRedirectUri('http://example.com/cb', error);

      url.format(redirectUri).should.equal('http://example.com/cb?error=invalid_client');
    });
  });

  describe('updateResponse()', function() {
    it('should set the `location` header', function() {
      var model = {
        getAccessToken: function() {},
        getClient: function() {},
        saveAuthorizationCode: function() {}
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
      var response = new Response({ body: {}, headers: {} });
      var uri = url.parse('http://example.com/cb');

      handler.updateResponse(response, uri, 'foobar');

      response.get('location').should.equal('http://example.com/cb?state=foobar');
    });
  });
});