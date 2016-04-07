var passport = require('passport');
var OAuth2Strategy = require('passport-oauth2').Strategy;
var request = require('request');
var generatePassword = require('password-generator');

module.exports = function(app, config) {    

    app.use(passport.initialize());
    app.use(passport.session());

    passport.use(new OAuth2Strategy(config.oauth2,
        function(accessToken, refreshToken, profile, done) {
            var password = generatePassword(16, false);
            var ttl = 1209600;

            if (!profile.id || !profile.emails[0] || !profile.emails[0].value) {
                return done("Wrong format of user profile");
            }

            var newUser = {
                id: profile.id,
                email: profile.emails[0].value,
                ttl: ttl,
                password: password,
                emailVerificationRequired: false,
                displayName: profile.displayName
            }

            app.models.User.findOrCreate({
                where: {
                    id: profile.id
                }
            }, newUser, function(err, user) {

                // Za in-memory uporabnika skreiramo še AccessToken na podlagi OAuth2 token-a, ki smo ga prejeli iz Auth strežnika  
                app.models.AccessToken.create({
                    id: accessToken,
                    ttl: ttl,
                    created: new Date().toISOString(),
                    userId: user.id
                }, function(err) {
                    if (err) return done(err);

                    // Iz objekta odstranimo geslo, da ga ne pošiljamo na Login stran 
                    delete user.password;

                    return done(null, user, { accessToken: accessToken });
                });
            });
        }
    ));

    passport.serializeUser(function(user, done) {
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

        request.get(options, function(err, response, body) {
            if (err) return done(err);

            if (response.statusCode === 200) {
                if (body[0] === '{') {
                    var profile = JSON.parse(body);
                    done(null, profile);
                } else {
                    done('Expected profile in JSON format');
                }

            } else {
                done(err);
            }
        });
    }
}