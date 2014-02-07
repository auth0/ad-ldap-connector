In addition to the steps in the tutorial you have to add an extra setting to the `config.json` file:

	"LDAP_USER_BY_NAME": "(&(handler={0}))",

Modify `lib/profileMapper.js` to map fields with topcoder schema:

	module.exports = function (raw_data) {

	  var profile = {
	    id:          raw_data.uid,
	    displayName: raw_data.handle,
	    nickname:    raw_data.handle,
	    status:      raw_data.status,
	  };

	  return profile;
	};

If you are deploying to CentOS follow the instructions in CENTOS.md to create a service.