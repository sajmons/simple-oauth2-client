var site = require('./site')
    , passport = require('passport');

module.exports = function (app) {
    app.get('/', site.root);
    app.get('/login', passport.authenticate('oauth2'), site.login);
    app.get('/redirect', site.redirect);
    app.get('/logout', site.logout);
    app.get('/auth/novavizija/callback', site.callback);    
};