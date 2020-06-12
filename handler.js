const user = require('./user');

module.exports.createUser = async event => {
  const body = JSON.parse(event.body);
  const newUser = await user.validate(body, null);
  let response = {
      statusCode: 200
  };
  if (newUser.errors) {
      response.body = JSON.stringify({errors: newUser.errors});
  } else {
      const savedUser = await user.save(newUser);
      response.body = JSON.stringify({user: savedUser});
  }
  return response;
};

module.exports.login = async event => {
  const body = JSON.parse(event.body);
  let response = {
      statusCode: 200
  };
  const responseBody = await user.login(body.email, body.password);
  response.body = JSON.stringify(responseBody);
  return response;
};

module.exports.authorizer = (event, context, callback) => {
    const userLookup = user.auth(event.authorizationToken, event.methodArn, (err, response) => {
        if (err) {
            callback(err);
        } else {
            callback(null, response);
        }
    });
};

module.exports.getUser = async event => {
    const currentUser = JSON.parse(event.requestContext.authorizer.user);
    const inputParams = event.pathParameters.email;

    if (inputParams !== currentUser.email && currentUser.roles.indexOf('admin') === -1) {
        return {
            statusCode: 401
        }
    }
    const body = JSON.stringify(await user.get(inputParams));
    return {
        statusCode: 200,
        body: body
    }
};

module.exports.updateUser = async event => {
    const currentUser = JSON.parse(event.requestContext.authorizer.user);
    const inputParams = event.pathParameters.email;
    const updates = JSON.parse(event.body);
    const denied = {statusCode: 401};
    if (inputParams !== currentUser.email && currentUser.roles.indexOf('admin') === -1) {
        return denied;
    } else if (currentUser.roles.indexOf('admin') === -1 && 'roles' in updates) {
        return denied;
    }

    const body = await user.update(inputParams, updates);
    return {
        statusCode: 200,
        body: JSON.stringify(body)
    };
};
