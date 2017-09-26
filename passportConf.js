var passport = require('passport');
var OAuth2Strategy = require('passport-oauth2').Strategy;
var request = require('request');

module.exports = function (app, config) {

    app.use(passport.initialize());
    app.use(passport.session());

    const cfg = {
        authorizationURL: config.oauth2.authorizationURL,
        tokenURL: config.oauth2.tokenURL,
        clientID: config.oauth2.clientID,
        clientSecret: config.oauth2.clientSecret,
        callbackURL: config.oauth2.callbackURL,
        scope: config.oauth2.scope
    }
    
    passport.use(new OAuth2Strategy(cfg,
        function (accessTokenId, refreshTokenId, profile, done) {
            if (!profile.id || !profile.emails[0] || !profile.emails[0].value) {
                return done(new Error("Wrong format of user profile"));
            }

            return done(null, profile, {
                accessToken: accessTokenId,
                refreshToken: refreshTokenId
            });
        }
    ));

    passport.serializeUser(function (user, done) {
        done(null, user.id);
    });

    passport.deserializeUser(function(id, done) {
        app.models.User.findById(id, function(err, user) {
            done(err, user);
        });
    });

    OAuth2Strategy.prototype.userProfile = getUserProfile;

    function getUserProfile(accessToken, done) {
        var options = {
            url: config.oauth2.profileURL,
            auth: {
                bearer: accessToken
            }
        };

        request.get(options, function (err, response, body) {
            if (err) return done(err);

            if (response.statusCode === 200) {
                if (body[0] === '{') {
                    var profile = JSON.parse(body);
                    done(null, profile);
                } else {
                    done(new Error('Expected profile in JSON format'));
                }

            } else {
                done(err);
            }
        });
    }
}