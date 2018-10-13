$(document).ready(function(){
	function init() {
		$('#answertype').change(showHide);
		console.log('init');
	}

	function showHide() {
		console.log($('#answertype option:selected').text());
		if ($('#answertype option:selected').text() == "Text") {
			$('#showOptions').css('display', 'none');
		} else {
			$('#showOptions').css('display', 'table');
		}
	}

	init();
})
