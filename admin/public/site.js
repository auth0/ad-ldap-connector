(function($) {
	var code = null;

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

			if (data.length > 1000) {
				$('#log-buttons-bottom').show();
			} else {
				$('#log-buttons-bottom').hide();
			}
		});
	}

	$('#troubleshoot-run').click(function(e) {
		e.preventDefault();

		$.get('/troubleshooter/run?_=' + new Date().getTime(), function(data) {
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

}(jQuery));