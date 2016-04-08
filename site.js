'use strict';

const passport = require('passport')
    , OAuth2Strategy = require('passport-oauth2').Strategy;

exports.root = function(req, res, next) {
    if (req.isAuthenticated()) {
        next();
    } else {
        res.redirect('/login');
    }
};

exports.login = function(req, res, next) {
    next();
};

exports.redirect = function(req, res, next) {
    req.session.returnTo = req.query.url;
    
    if (req.isAuthenticated()) {
        return res.redirect("/?redirect_url=" + encodeURIComponent(req.query.url));
    } else {    
        res.redirect("/login");
    }
};

exports.callback = function(req, res, next) {

    if (req.query.error) {
        return res.sendStatus(403);
    } else {
        passport.authenticate('oauth2', function(err, user, info) {
            if (err) {
                return next(err);
            }

            if (!user) {
                return res.redirect('/login');
            }
            
            var accessToken = info.accessToken;

            req.logIn(user, function(err) {
                if (err) {
                    return next(err);
                }
     
                var config = app.get('config');
     
                res.cookie(config.oauth2.cookie, accessToken);
                
                var returnTo = req.session.returnTo;  
                if (returnTo) {
                    delete req.session.returnTo;
                    return res.redirect("/?redirect_url=" + encodeURIComponent(returnTo));
                } else {                
                    return res.redirect('/');
                }
            });
        })(req, res, next);
    }
};

exports.logout = function(req, res, next) {

    if (!req.isAuthenticated()) return res.sendStatus(401);

    req.app.models.AccessToken.findOne({
        where: { userId: req.user.id }
    }, function(err, token) {
        if (err) return res.sendStatus(401);

        req.logout();

        // Odjavimo uporabnika glede na njegov access_token
        req.app.models.User.logout(token.id, function(error) {
            if (error) return next(error);

            var config = app.get('config');

            res.clearCookie(config.oauth2.cookie);

            var logoutUrl = config.oauth2.authorizationHost
                + '/logout?redirect_url=' + config['https-url']
                + '/login&access_token=' + token.id;

            res.redirect(logoutUrl);
        });
    });

};