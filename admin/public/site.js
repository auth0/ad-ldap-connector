(function($) {
	var code = null;

	$.get('/version?_=' + new Date().getTime(), function(p) {

		$('#connector-version').text('v' + p);

		$.get('https://cdn.auth0.com/connector/windows/latest.json?_=' + new Date().getTime(), function(data) {
			var tab = $('#update-tab');
			if (tab.length > 0) {
				tab.show();
				tab.css('display', 'block');

				// New version available.
				if (p !== data.version) {
					$('#update-version').text(data.version);
					$('#update-available').show();
				}
			}
		});
	});

	$('.nav-tabs a').on('shown', function(e) {
		scrollToTop();

		if ($(this).prop('hash') === '#troubleshooting') {
			getLogs();
		} else if ($(this).prop('hash') === '#profile-mapper') {
			if (code == null) {
				code = CodeMirror(document.getElementById('profile-mapper-editor'), {
					mode: "javascript",
					lineNumbers: true,
					styleActiveLine: true,
					matchBrackets: true
				});

				$.get('/profile-mapper?_=' + new Date().getTime(), function(data) {
					code.setValue(data);
				});
			}
		}
	});

	$('#update-show').click(function (e) {
		$('.nav-tabs a[href="/#update"]').tab('show');
	});

	$('.nav-tabs a').click(function(e) {
		$(this).tab('show');
	});

	$('.nav-tabs a[href="/' + window.location.hash + '"]').tab('show');

	$("#profile-mapper").submit(function(e) {
		e.preventDefault();

		$('#profile-mapper-alerts').html('');

		$.post('/profile-mapper', {
			code: code.getValue()
		}).done(function() {
			$('#profile-mapper-alerts')
				.html('<div class="alert alert-success"><button type="button" class="close" data-dismiss="alert">&times;</button>The profile mapper script has been saved.</div>');
		}).fail(function(err) {
			$('#profile-mapper-alerts')
				.html('<div class="alert alert-error"><button type="button" class="close" data-dismiss="alert">&times;</button>Error saving the profile mapper script. Error: ' + err.statusText + '</div>');
		});
	});

	$("#scroll-top").click(function(e) {
		e.preventDefault();

		scrollToTop();
	});

	function scrollToTop() {
		setTimeout(function() {
			window.scrollTo(0, 0);
		}, 10);
	}

	$("#scroll-bottom").click(function(e) {
		e.preventDefault();

		scrollToEnd();
	});

	function scrollToEnd() {
		setTimeout(function() {
			window.scrollTo(0, document.body.scrollHeight);
		}, 10);
	}

	$(".logs-read").click(function(e) {
		e.preventDefault();

		getLogs();
	});

	$("#logs-clear").click(function(e) {
		e.preventDefault();

		$.post('/logs/clear');
		$('#logs').text('');
	});

	setInterval(getLogs, 5000);

	function getLogs() {
		$.get('/logs?_=' + new Date().getTime(), function(data) {
			$('#logs').text(data);

			if (data.length > 2500) {
				$('#log-buttons-bottom').show();
			} else {
				$('#log-buttons-bottom').hide();
			}
		});
	}

	$('#troubleshoot-run').click(function(e) {
		e.preventDefault();

		$('#troubleshoot-progress').show();
		$('#troubleshoot-output').hide();
		$('#troubleshoot-output').html('');

		$.get('/troubleshooter/run?_=' + new Date().getTime(), function(data) {

			$('#troubleshoot-progress').hide();
			$('#troubleshoot-output').show();
			$('#troubleshoot-output').html(data
				.replace(/\info\:/g, '<span class="troubleshoot-info">info</span>:')
				.replace(/\warn\:/g, '<span class="troubleshoot-warning">warn</span>:')
				.replace(/\error\:/g, '<span class="troubleshoot-error">error</span>:')
				.trim());

			return;
			var list = $('#troubleshoot-output').html('<ul />').find('ul');

			$.each(data, function(i, item) {
				if (item.result === 'OK') {
					list.append('<li>' + item.proof + ' (<span style="color: green">OK</span>)');
				} else {
					list.append('<li>' + item.proof + ' (<span style="color: red">NOT OK</span>)');
				}
			});
		});
	});

	var update = "None";

	$("#update-run-form").submit(function(e) {
		e.preventDefault();

		$.post('/updater/run');
		
		update = 'Started';
		$('#update-logs').text('');
		$('#update-progress').show();
		$('#update-available').hide();
	});

	function getUpdaterLogs() {
		$.get('/updater/logs?_=' + new Date().getTime(), function(data) {
			if (data && data.length > 0) {
				$('#update-logs').html(data
					.replace(/\DEBUG\:/g, '<span class="troubleshoot-info">DEBUG</span>:')
					.replace(/\INFO\:/g, '<span class="troubleshoot-success">INFO</span>:')
					.replace(/\ERROR\:/g, '<span class="troubleshoot-error">ERROR</span>:'));
				$('#update-logs-widget').show();

				if (data.indexOf('(Installation-Stop)') >= 0) {
					update = 'None';
					$('#update-progress').hide();
				}
			}
		})
		.done(function() {
			if (update === 'Busy') {
				update = 'None';
				$('#update-progress').hide();
			}
		})
		.fail(function(err) {
			if (update === 'Started') {
				update = 'Busy';
			}
		});
	}

	setInterval(getUpdaterLogs, 2500);
	getUpdaterLogs();

}(jQuery));