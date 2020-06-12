const supertest = require('supertest');
const chai = require('chai');
const chaiHttp = require('chai-http');
const should = chai.should();
chai.use(chaiHttp);
const endpoint = 'http://localhost:3000/local';
const client = supertest(endpoint);
const aws = require('aws-sdk');
const handler = require('../handler');
let token;
let session;
const docClient = new aws.DynamoDB.DocumentClient({
    "region": "us-west-2",
    "endpoint": "http://localhost:8000"
});
const environment = process.env.AWS_ENV || 'local';
const userTable = `users-${environment}`;
const sessionTable = `auth-sessions-${environment}`;

const scanTable = (tableName) => {
    return docClient.scan({ TableName: tableName }).promise();
};

const deleteItems = (items, table, key) => {
    return items.map((item) => {
        const params = {
            TableName: table,
            Key: {
                key: item[key]
            }
        };
        return docClient.delete(params).promise();
    })
};

describe('Create user', () => {
    before(async () => {
        console.log('Scanning users and sessions...');
        const users = scanTable(userTable);
        const sessions = scanTable(sessionTable);
        const cleanup = await Promise.all([users, sessions]);
        console.log('Got all users and sessions...');
        const deletes = cleanup[0].Items.map((user) => {
            const p = {
                TableName: userTable,
                Key: {
                    'email': user.email
                }
            };
            return docClient.delete(p).promise();
        });
        const deleteSessions = cleanup[1].Items.map((session) => {
            const p = {
                TableName: sessionTable,
                Key: {
                    'tokenId': session.tokenId
                }
            };
            return docClient.delete(p).promise();
        });
        await Promise.all([...deletes, ...deleteSessions]);
        const expiredSession = {
            TableName: sessionTable,
            Item: {
                tokenId: 'expired',
                email: 'expired@expired.com',
                createdAt: (new Date().getTime() - (121 * 60 * 60 * 1000)),
                lastUsed: (new Date().getTime() - (121 * 60 * 60 * 1000))
            }
        };
        await docClient.put(expiredSession).promise();
    });

    describe('Basic validation', async () => {
        let adminUser;
        it('Should have an event body', async () => {
            const res = await client.post('/user');
            res.should.have.status(200);
            res.body.errors.length.should.be.at.least(1);
        });

        it('Should have an email', async () => {
            const res = await client.post('/user');
            res.should.have.status(200);
            res.body.errors.length.should.be.at.least(1);
        });

        it('Should ensure the email passes a basic regex for an email', async () => {
            const res = await client.post('/user')
                .send({ 'email': 'yolo' });
            res.should.have.status(200);
            res.body.errors.length.should.be.at.least(1);
        });

        it('Should require a first name', async () => {
            const res = await client.post('/user')
                .send({ 'email': 'test@test.com' });
            res.should.have.status(200);
            res.body.errors.length.should.be.at.least(1);
        });

        it('Should require the first name to be at least one character long', async () => {
            const res = await client.post('/user')
                .send({ 'email': 'test@test.com', 'first_name': '' });
            res.should.have.status(200);
            res.body.errors.length.should.be.at.least(1);
        });

        it('Should require a last name', async () => {
            const res = await client.post('/user')
                .send({ 'email': 'test@test.com', 'first_name': 'test' });
            res.should.have.status(200);
            res.body.errors.length.should.be.at.least(1);
        });

        it('Should require the last name to be at least one character long', async () => {
            const res = await client.post('/user')
                .send({ 'email': 'test@test.com', 'first_name': 'test', 'last_name': '' });
            res.should.have.status(200);
            res.body.errors.length.should.be.at.least(1);
        });

        it('Should require a password and the password should be at least 8 characters', async () => {
            const res = await client.post('/user')
                .send({ 'email': 'test@test.com', 'first_name': 'test', 'last_name': 'testerson', 'password': 'pass' });
            res.should.have.status(200);
            res.body.errors.length.should.be.at.least(1);
        });

        it('Should ensure that the password and verify password are the same', async () => {
            const res = await client.post('/user')
                .send({
                    'email': 'test@test.com',
                    'first_name': 'test',
                    'last_name': 'testerson',
                    'password': 'password',
                    'verify_password': 'pass'
                });
            res.should.have.status(200);
            res.body.errors.length.should.be.at.least(1);
        });

        it('Should return a user object in the response if all validations pass', async () => {
            const res = await client.post('/user')
                .send({
                    'email': 'test@test.com',
                    'first_name': 'test',
                    'last_name': 'testerson',
                    'password': 'password',
                    'verify_password': 'password'
                });
            res.should.have.status(200);
            res.body.user.should.exist;
            res.body.user.roles.should.exist;
        });

        it('Should return an empty array for user.roles regardless of what is submitted', async () => {
            const res = await client.post('/user')
                .send({
                    'email': 'test2@test.com',
                    'first_name': 'test',
                    'last_name': 'testerson',
                    'roles': ['admin'],
                    'password': 'password',
                    'verify_password': 'password'
                });
            res.should.have.status(200);
            res.body.user.roles.length.should.equal(0);
        });

        it('Should reject a post that contains invalid keys', async () => {
            const res = await client.post('/user')
                .send({ 'email': 'test@test.com', 'first_name': 'test', 'last_name': 'testerson', 'foo': 'bar' });
            res.should.have.status(200);
            res.body.errors.length.should.be.at.least(1);
        });

        it('Should have saved 2 users in dynamo', async () => {
            const params = {
                TableName: userTable
            };
            const users = await docClient.scan(params).promise();
            users.Count.should.equal(2);
        });

        it('Should ensure emails are unique', async () => {
            const res = await client.post('/user')
                .send({
                    'email': 'test@test.com',
                    'first_name': 'test',
                    'last_name': 'testerson',
                    'password': 'password',
                    'verify_password': 'password'
                });
            res.should.have.status(200);
            res.body.errors.length.should.be.at.least(1);
        });

        it('Should encrypt the password when it is stored', async () => {
            const res = await client.post('/user')
                .send({
                    'email': 'richard.cheese@yahoo.com',
                    'first_name': 'richard',
                    'last_name': 'cheese',
                    'password': 'password',
                    'verify_password': 'password'
                });
            res.should.have.status(200);
            res.body.user.password.should.not.equal('password');
        });

        it('Should have a timestamp for createdAt and modifiedAt and they should be the same', async () => {
            const res = await client.post('/user')
                .send({
                    'email': 'russell.wilson@seahawks.com',
                    'first_name': 'russell',
                    'last_name': 'wilson',
                    'password': 'password',
                    'verify_password': 'password'
                });
            res.should.have.status(200);
            adminUser = res.body.user;
            adminUser.createdAt.should.equal(res.body.user.modifiedAt);
        });

        after(async () => {
            adminUser.roles = ['admin'];
            const params = {
                TableName: userTable,
                Item: adminUser
            };
            await docClient.put(params).promise();
        })
    });

    describe('Allow a user to receive a login session', async () => {
        it('Should return an error if email is not provided', async () => {
            const res = await client.post('/user/login')
                .send({ 'password': 'password' });
            res.should.have.status(200);
            res.body.errors.length.should.be.at.least(1);
        });

        it('Should return an error if email is an empty string', async () => {
            const res = await client.post('/user/login')
                .send({ 'email': '', 'password': 'password' });
            res.should.have.status(200);
            res.body.errors.length.should.be.at.least(1);
        });

        it('Should provide an error if the user cannot be found', async () => {
            const res = await client.post('/user/login')
                .send({ 'email': 'cannotfind@somewhere.com', 'password': 'password' });
            res.should.have.status(200);
            res.body.errors.length.should.be.at.least(1);
        });

        it('Should provide an error if the password does not match', async () => {
            const res = await client.post('/user/login')
                .send({ 'email': 'test@test.com', 'password': 'password123' });
            res.should.have.status(200);
            res.body.errors.length.should.be.at.least(1);
        });

        it('Should return a token if the login is successful', async () => {
            const res = await client.post('/user/login')
                .send({ 'email': 'test@test.com', 'password': 'password' });
            res.should.have.status(200);
            res.body.token.should.exist;
            token = res.body.token;
        });

        it('Should store the session in Dynamo', async () => {
            const params = {
                TableName: sessionTable,
                KeyConditionExpression: 'tokenId = :token',
                ExpressionAttributeValues: {
                    ':token': token
                }
            };
            const sessionLookUp = await docClient.query(params).promise();
            session = sessionLookUp.Items[0];
            sessionLookUp.Count.should.equal(1);
        });

        it('Should have the email of the user in the session table', () => {
            session.email.should.equal('test@test.com');
        });

        it('Should have a createdAt and lastUsed that are the same on login', () => {
            session.createdAt.should.equal(session.lastUsed);
        })
    });

    describe('Authorized users should be able to get a user based on email', async () => {
        it('Should give a 401 if a non admin user tries to access a different user\'s info', async () => {
            const res = await client.post('/user/login')
                .send({ 'email': 'test@test.com', 'password': 'password' });
            const token = res.body.token;
            const getResult = await client.get('/user/test2@test.com')
                .set('Authorization', token);
            getResult.statusCode.should.equal(401);
        });

        it('Should receive a 200 if an admin user tries to access a different user\'s info', async () => {
            const res = await client.post('/user/login')
                .send({ 'email': 'russell.wilson@seahawks.com', 'password': 'password' });
            const token = res.body.token;
            const getResult = await client.get('/user/test2@test.com')
                .set('Authorization', token);
            getResult.statusCode.should.equal(200);
        });

        it('Should receive the user object if the user requests their own info', async () => {
            const res = await client.post('/user/login')
                .send({ 'email': 'test2@test.com', 'password': 'password' });
            const token = res.body.token;
            const getResult = await client.get('/user/test2@test.com')
                .set('Authorization', token);
            getResult.statusCode.should.equal(200);
            getResult.body.email.should.equal('test2@test.com');
        })
    });

    describe('Allow updates', async () => {
        const regUser = {
            createdAt: 1580234005407,
            password: '$2a$10$Sv2XDdjyqji7hdZonYnwJ.SUDZT1D5c7GQ8Ppm2DfcLeGTYWmLMXu',
            modifiedAt: 1580234005407,
            roles: [],
            last_name: 'testerson',
            first_name: 'test',
            email: 'test@test.com'
        };
        const adminUser = {
            createdAt: 1580234005407,
            password: '$2a$10$Sv2XDdjyqji7hdZonYnwJ.SUDZT1D5c7GQ8Ppm2DfcLeGTYWmLMXu',
            modifiedAt: 1580234005407,
            roles: ['admin'],
            last_name: 'wilson',
            first_name: 'russell',
            email: 'russell.wilson@seahawks.com'
        };
        it('Should return an error if the user cannot be found', async () => {
            const res = await client.post('/user/login')
                .send({ 'email': 'russell.wilson@seahawks.com', 'password': 'password' });
            const token = res.body.token;
            const getResult = await client.put('/user/fake@test.com')
                .set('Authorization', token)
                .send({ 'first_name': 'somethingelse' });
            getResult.statusCode.should.equal(200);
            getResult.body.errors.should.exist;
        });

        it('Should not allow a non admin to update a user that is not themselves', async () => {
            const res = await client.post('/user/login')
                .send({ 'email': 'richard.cheese@yahoo.com', 'password': 'password' });
            const token = res.body.token;
            const getResult = await client.put('/user/russell.wilson@seahawks.com')
                .set('Authorization', token)
                .send({ 'first_name': 'Russ' });
            getResult.statusCode.should.equal(401);
        });

        it('Should allow a user to update selected fields', async () => {
            const res = await client.post('/user/login')
                .send({ 'email': 'richard.cheese@yahoo.com', 'password': 'password' });
            const token = res.body.token;
            const getResult = await client.put('/user/richard.cheese@yahoo.com')
                .set('Authorization', token)
                .send({ 'first_name': 'Ricardo' });
            getResult.statusCode.should.equal(200);
            getResult.body.first_name.should.equal('Ricardo');
        });

        it('Should not allow email address to be updated', async () => {
            const res = await client.post('/user/login')
                .send({ 'email': 'richard.cheese@yahoo.com', 'password': 'password' });
            const token = res.body.token;
            const getResult = await client.put('/user/richard.cheese@yahoo.com')
                .set('Authorization', token)
                .send({ 'email': 'somethingelse@fake.com' });
            getResult.statusCode.should.equal(200);
            getResult.body.errors.should.exist;
        });

        it('Should require a verify_password if a password is present', async () => {
            const res = await client.post('/user/login')
                .send({ 'email': 'richard.cheese@yahoo.com', 'password': 'password' });
            const token = res.body.token;
            const getResult = await client.put('/user/richard.cheese@yahoo.com')
                .set('Authorization', token)
                .send({ 'first_name': 'testy', 'password': 'password123iswaymoresecure' });
            getResult.statusCode.should.equal(200);
            getResult.body.errors.should.exist;
        });

        it('Should change and encrypt the password if password and verify password are present', async () => {
            const res = await client.post('/user/login')
                .send({ 'email': 'richard.cheese@yahoo.com', 'password': 'password' });
            const token = res.body.token;
            const getResult = await client.put('/user/richard.cheese@yahoo.com')
                .set('Authorization', token)
                .send({ 'first_name': 'testy', 'password': 'password123iswaymoresecure', 'verify_password': 'password123iswaymoresecure' });
            getResult.statusCode.should.equal(200);
            getResult.body.password.should.not.equal('password123iswaymoresecure');
            let verify_password = 'YOLO';
            if (getResult.body.verify_password === undefined) {
                verify_password = 'undefined';
            }
            verify_password.should.equal('undefined');
        });

        it('Should not allow a non admin user to modify a role', async () => {
            const res = await client.post('/user/login')
                .send({ 'email': 'test@test.com', 'password': 'password' });
            const token = res.body.token;
            const getResult = await client.put('/user/test@test.com')
                .set('Authorization', token)
                .send({ 'first_name': 'testy', roles: ['admin'] });
            getResult.statusCode.should.equal(401);
        });

        it('Should allow an admin to modify a user\'s role', async () => {
            const res = await client.post('/user/login')
                .send({ 'email': 'russell.wilson@seahawks.com', 'password': 'password' });
            const token = res.body.token;
            const getResult = await client.put('/user/test@test.com')
                .set('Authorization', token)
                .send({ roles: ['admin'] });
            getResult.statusCode.should.equal(200);
            getResult.body.roles.indexOf('admin').should.not.equal(-1);
        })
    })
});