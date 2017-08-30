'use strict';

const passport = require('passport')
    , OAuth2Strategy = require('passport-oauth2').Strategy
    , request = require('request')
    , debug = require('debug')('simple-oauth2-client') 

exports.root = function (req, res, next) {
    if (req.isAuthenticated()) {
        next();
    } else {
        res.redirect("/login");
    }
};

exports.login = function (req, res, next) {
    next();
};

exports.redirect = function (req, res, next) {
    if (req.isAuthenticated()) {
        req.session.returnTo = req.query.redirect_url;
        return res.redirect("/?redirect_url=" + encodeURIComponent(req.query.url));
    } else {
        res.redirect("/login");
    }
};

exports.callback = function (req, res, next) {

    if (req.query.error) {
        return res.sendStatus(403);
    } else {
        passport.authenticate('oauth2', function (err, user, info) {
            if (err) {
                return next(err);
            }

            if (!user) {
                return res.redirect('/login');
            }

            req.logIn(user, function (err) {
                if (err) {
                    return next(err);
                }

                var config = app.get('config');

                res.cookie(config.oauth2.cookie, info.accessToken);
                req.session.refresh_token = info.refreshToken;

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

exports.logout = function (req, res, next) {

    if (!req.isAuthenticated()) return res.sendStatus(401);

    req.logout();

    var config = app.get('config');

    res.clearCookie(config.oauth2.cookie);

    if (!config['url']) {
        res.status(400).send("Missing url setting in config.json");
        return;
    }

    var logoutUrl = config.oauth2.authorizationHost
        + '/logout?redirect_url=' + config['url']
        + '/login&access_token=' + req.query.access_token;

    debug("LogoutURL: %s", logoutUrl);

    res.redirect(logoutUrl);

};

exports.refreshToken = function (req, res, next) {
    req.session.redirect_url = req.query.redirect_url;

    var config = app.get('config');

    if (req.isAuthenticated()) {

        var options = {
            url: config.oauth2.tokenURL,
            method: 'POST',
            headers: {
                'Authorization': "Basic " + new Buffer(config.oauth2.clientID + ":" + config.oauth2.clientSecret).toString("base64")
            },
            form: {
                grant_type: 'refresh_token',
                refresh_token: req.session.refresh_token
            }
        };

        request.post(options, function (err, httpResponse, body) {
            if (err || httpResponse.statusCode !== 200) {
                next(body);
            } else {
                res.clearCookie(config.oauth2.cookie);

                var token = JSON.parse(body);

                res.cookie(config.oauth2.cookie, token.access_token);
                req.session.refresh_token = token.refresh_token;

                var redirect_url = req.session.redirect_url;
                delete req.session.redirect_url;
                res.redirect(redirect_url);
            }
        });
    } else {
        res.redirect("/login");
    }
};