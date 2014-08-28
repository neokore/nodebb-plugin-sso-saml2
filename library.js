(function(module) {
	"use strict";

	var user = module.parent.require('./user'),
		meta = module.parent.require('./meta'),
		db = module.parent.require('../src/database'),
		passport = module.parent.require('passport'),
		passportSaml = require('passport-saml').Strategy,
		fs = module.parent.require('fs'),
		path = module.parent.require('path'),
		nconf = module.parent.require('nconf');

	var constants = Object.freeze({
		'name': "Saml",
		'admin': {
			'route': '/plugins/sso-saml2',
			'icon': 'fa-saml-square'
		}
	});

	var Saml = {};

	Saml.init = function(app, middleware, controllers, callback) {
		function render(req, res, next) {
			res.render('admin/plugins/sso-saml2', {});
		}

		app.get('/admin/plugins/sso-saml2', middleware.admin.buildHeader, render);
		app.get('/api/admin/plugins/sso-saml2', render);

		callback();
	};

	Saml.getStrategy = function(strategies, callback) {
		if (meta.config['social:twitter:key'] && meta.config['social:twitter:secret']) {
			passport.use(new passportTwitter({
				consumerKey: meta.config['social:twitter:key'],
				consumerSecret: meta.config['social:twitter:secret'],
				callbackURL: nconf.get('url') + '/auth/twitter/callback'
			}, function(token, tokenSecret, profile, done) {
				Saml.login(profile.id, profile.username, profile.photos, function(err, user) {
					if (err) {
						return done(err);
					}
					done(null, user);
				});
			}));

			strategies.push({
				name: 'twitter',
				url: '/auth/twitter',
				callbackURL: '/auth/twitter/callback',
				icon: constants.admin.icon,
				scope: ''
			});
		}

		callback(null, strategies);
	};

	Saml.login = function(twid, handle, photos, callback) {
		Saml.getUidByTwitterId(twid, function(err, uid) {
			if(err) {
				return callback(err);
			}

			if (uid !== null) {
				// Existing User
				callback(null, {
					uid: uid
				});
			} else {
				// New User
				user.create({username: handle}, function(err, uid) {
					if(err) {
						return callback(err);
					}

					// Save twitter-specific information to the user
					user.setUserField(uid, 'twid', twid);
					db.setObjectField('twid:uid', twid, uid);

					// Save their photo, if present
					if (photos && photos.length > 0) {
						var photoUrl = photos[0].value;
						photoUrl = path.dirname(photoUrl) + '/' + path.basename(photoUrl, path.extname(photoUrl)).slice(0, -6) + 'bigger' + path.extname(photoUrl);
						user.setUserField(uid, 'uploadedpicture', photoUrl);
						user.setUserField(uid, 'picture', photoUrl);
					}

					callback(null, {
						uid: uid
					});
				});
			}
		});
	};

	Saml.getUidByTwitterId = function(twid, callback) {
		db.getObjectField('twid:uid', twid, function(err, uid) {
			if (err) {
				return callback(err);
			}
			callback(null, uid);
		});
	};

	Saml.addMenuItem = function(custom_header, callback) {
		custom_header.authentication.push({
			"route": constants.admin.route,
			"icon": constants.admin.icon,
			"name": constants.name
		});

		callback(null, custom_header);
	};

	module.exports = Saml;
}(module));
