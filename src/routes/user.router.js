const { getAll, create, getOne, remove, update, verifyUser, login, getMe, resetPassword, changePassword } = require('../controllers/user.controllers');
const express = require('express');
const { verifyJwt } = require('../utils/verifyJwt');

const routerUser = express.Router();

routerUser.route('/')
    .get(verifyJwt, getAll)
    .post(create);

routerUser.route('/login')
    .post(login)

routerUser.route('/me')
    .get(verifyJwt, getMe)

routerUser.route('/verify/:code')    
    .get(verifyUser);

routerUser.route('/reset_password')    
    .post(resetPassword);    

routerUser.route('/reset_password/:code')    
    .post(changePassword);

routerUser.route('/:id')
    .get(verifyJwt, getOne)
    .delete(verifyJwt, remove)
    .put(verifyJwt, update);

module.exports = routerUser;