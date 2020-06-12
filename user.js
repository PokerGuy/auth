const aws = require('aws-sdk');
const bcrypt = require('bcryptjs');
const uuid = require('uuid/v4');
const validFields = ['email', 'last_name', 'first_name', 'password', 'roles', 'createdAt', 'modifiedAt'];
const re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;

const getUserTable = () => {
    if (process.env.AWS_ENV && process.env.AWS_ENV != 'undefined') {
        return `users-${process.env.AWS_ENV}`
    }
    return 'users-local';
};

const getSessionTable = () => {
    if (process.env.AWS_ENV && process.env.AWS_ENV != 'undefined') {
        return `auth-sessions-${process.env.AWS_ENV}`
    }
    return 'auth-sessions-local';
};

const getDocClient = () => {
    if (process.env.ENVIRONMENT === undefined || process.env.ENVIRONMENT === 'local') {
        return new aws.DynamoDB.DocumentClient({
            "region": "us-west-2",
            "endpoint": "http://localhost:8000"
        })
    } else {
        return new aws.DynamoDB.DocumentClient({
            "region": process.env.REGION
        })
    }
};

module.exports.validate = async (user, updates) => {
    let errors = [];
    const docClient = getDocClient();
    if ((user === null)) {
        errors.push('Body is missing in HTTP Post.');
    } else {
        if (!('email' in user) && updates === null) {
            errors.push('Email is missing.');
        } else if (!(re.test(user.email)) && updates === null) {
            errors.push('Email is not formatted properly.')
        } else if (updates === null) {
            const params = {
                TableName: getUserTable(),
                KeyConditionExpression: 'email = :email',
                ExpressionAttributeValues: {
                    ':email': user.email
                }
            };
            const userCheck = await docClient.query(params).promise();
            if (userCheck.Count > 0) {
                errors.push('Email is not unique.');
            }
        }

        if (updates && 'email' in updates) {
            errors.push('Email cannot be changed')
        }

        if (user.first_name === null || user.first_name === undefined) {
            errors.push('first_name is missing.');
        } else if (user.first_name.length < 1) {
            errors.push('first_name must be at least one character.');
        }

        if (user.last_name === null || user.last_name === undefined) {
            errors.push('last_name is missing.');
        } else if (user.last_name.length < 1) {
            errors.push('last_name must be at least one character.');
        }

        if (updates === null) {
            user.roles = [];
            delete user.createdAt;
            delete user.modifiedAt;
            if ((user.password === null || user.password === undefined) && updates === null) {
                errors.push('Password is missing.');
            } else if (user.password.length < 8 && updates === null) {
                errors.push('Password must be at least eight characters.');
            }
            if (user.verify_password === null || user.verify_password === undefined) {
                errors.push('verify_password is missing.');
            } else if (user.password !== user.verify_password) {
                errors.push('password and verify password do not match.');
            } else {
                delete user.verify_password;
            }
        } else {
            if ('password' in updates) {
                if (!('verify_password' in updates)) {
                    errors.push('verify_password must be provided to update password.')
                } else if (updates.verify_password !== updates.password) {
                    errors.push('verify_password and password do not match.')
                } else if (updates.password.length < 8) {
                    errors.push('password must be at least 8 characters.')
                } else {
                    updates.password = encryptPassword(updates.password, user.createdAt);
                    delete updates.verify_password;
                }
            }
        }

        Object.keys(user).forEach((key) => {
            if (validFields.indexOf(key) === -1) {
                errors.push(`${key} is an invalid field.`);
            }
        });

    }


    if (errors.length > 0) {
        return { errors: errors };
    } else {
        if (updates === null) {
            user.createdAt = new Date().getTime();
            user.password = encryptPassword(user.password, user.createdAt);
            return user;
        } else {
            return updates;
        }
    }
}
    ;

const encryptPassword = (password, saltDate) => {
    const salt = bcrypt.genSaltSync(10);
    const encrypted = bcrypt.hashSync(`${password}|${saltDate}`, salt);
    return encrypted;
};

module.exports.save = async user => {
    if (!('modifiedAt' in user)) {
        user.modifiedAt = user.createdAt;
    } else {
        user.modifiedAt = new Date().getTime();
    }
    const docClient = getDocClient();
    const params = {
        TableName: getUserTable(),
        Item: user
    };
    await docClient.put(params).promise();
    return user;
};

module.exports.login = async (email, password) => {
    if (email === null || email === undefined || password === null || password === undefined || email === '' || password === '') {
        return { errors: ['Missing email or password.'] };
    }
    const docClient = getDocClient();
    const params = {
        TableName: getUserTable(),
        KeyConditionExpression: 'email = :email',
        ExpressionAttributeValues: {
            ':email': email
        }
    };
    const userLookUp = await docClient.query(params).promise();
    if (userLookUp.Count === 0) {
        return { errors: ['Incorrect email or password.'] };
    }

    const user = userLookUp.Items[0];
    if (!(bcrypt.compareSync(`${password}|${user.createdAt}`, user.password))) {
        return { errors: ['Incorrect email or password.'] };
    }

    const token = uuid();
    const createdAt = new Date().getTime();
    const p = {
        TableName: getSessionTable(),
        Item: {
            tokenId: token,
            email: email,
            createdAt: createdAt,
            lastUsed: createdAt
        }
    };
    await docClient.put(p).promise();

    return { token: token, user: user };
};

module.exports.auth = (token, method, callback) => {
    const docClient = getDocClient();
    const params = {
        TableName: getSessionTable(),
        KeyConditionExpression: 'tokenId = :token',
        ExpressionAttributeValues: {
            ':token': token
        }
    };
    docClient.query(params, (err, data) => {
        if (err || data.Count === 0) {
            callback('Unauthorized', null);
        } else {
            let session = data.Items[0];
            if (session.lastUsed < (new Date().getTime() - (120 * 60 * 60 * 1000))) {
                callback('Unauthorized', null);
            }
            session.lastUsed = new Date().getTime();
            const updateParams = {
                TableName: getSessionTable(),
                Item: session
            };
            docClient.put(updateParams, (updateError, updateData) => {
                const p = {
                    TableName: getUserTable(),
                    KeyConditionExpression: 'email = :email',
                    ExpressionAttributeValues: {
                        ':email': session.email
                    }
                };
                docClient.query(p, (error, userData) => {
                    if (error || userData.Count === 0) {
                        callback('Unauthorized', null);
                    } else {
                        let response = generatePolicy(method, userData.Items[0].email);
                        response.context = { user: JSON.stringify(userData.Items[0]) };
                        callback(null, response);
                    }
                });
            });
        }
    })
};

module.exports.get = async email => {
    const docClient = getDocClient();
    const params = {
        TableName: getUserTable(),
        KeyConditionExpression: 'email = :email',
        ExpressionAttributeValues: {
            ':email': email
        }
    };
    const user = await docClient.query(params).promise();
    if (user.Count === 1) {
        return user.Items[0];
    } else {
        return {};
    }
};

module.exports.update = async (email, updates) => {
    const docClient = getDocClient();
    const currParams = {
        TableName: getUserTable(),
        KeyConditionExpression: 'email = :email',
        ExpressionAttributeValues: {
            ':email': email
        }
    };
    const currentUserQuery = await docClient.query(currParams).promise();
    if (currentUserQuery.Count !== 1) {
        return { errors: ['Invalid user email provided'] };
    }
    const currentUser = currentUserQuery.Items[0];
    const validation = await this.validate(currentUser, updates);

    if ('errors' in validation) {
        return { errors: validation.errors };
    }

    const update = { ...currentUser, ...validation };
    await this.save(update);
    return update;
};

const generatePolicy = (methodArn, email) => {
    let response = {};
    response.principalId = email;
    let policyDocument = {};
    policyDocument.Version = '2012-10-17';
    policyDocument.Statement = [];
    let statementOne = {};
    statementOne.Action = 'execute-api:Invoke';
    statementOne.Effect = 'Allow';
    const parsedArn = methodArn.split(':');
    statementOne.Resource = `${parsedArn[0]}:${parsedArn[1]}:${parsedArn[2]}:${parsedArn[3]}:${parsedArn[4]}:*/*/*/*`;
    policyDocument.Statement[0] = statementOne;
    response.policyDocument = policyDocument;
    return response;
};