$(function() {

  var btnSbTrigger = $('#sidebar-trigger');
  var btnSearchTrigger = $('#search-trigger');
  var btnCancel = $('#search-cancel');
  var btnClear = $('#search-cleaner');

  var main = $('#main');
  var topbarTitle = $('#topbar-title');
  var searchWrapper = $('#search-wrapper');
  var resultWrapper = $('#search-result-wrapper');
  var results = $('#search-results');
  var input = $('#search-input');
  var hints = $('#search-hints');


  /*--- Actions in small screens (Sidebar unloaded) ---*/

  var scrollBlocker = (function() {
    var offset = 0;
    return {
      block: function() {
        offset = $(window).scrollTop();
        $('body').addClass('no-scroll');
      },
      release: function() {
        $('body').removeClass('no-scroll');
        $('html,body').scrollTop(offset);
      },
      getOffset: function() {
        return offset;
      }
    }
  })();

  var mobileSearchBar = (function() {
    return {
      on: function() {
        btnSbTrigger.addClass('unloaded');
        topbarTitle.addClass('unloaded');
        btnSearchTrigger.addClass('unloaded');
        searchWrapper.addClass('d-flex');
        btnCancel.addClass('loaded');
      },
      off: function() {
        btnCancel.removeClass('loaded');
        searchWrapper.removeClass('d-flex');
        btnSbTrigger.removeClass('unloaded');
        topbarTitle.removeClass('unloaded');
        btnSearchTrigger.removeClass('unloaded');
      }
    }
  })();

  var resultSwitch = (function() {
    var visable = false;

    return {
      on: function() {
        if (!visable) {
          resultWrapper.removeClass('unloaded');
          main.addClass('hidden');

          visable = true;
          scrollBlocker.block();
        }
      },
      off: function() {
        if (visable) {
          results.empty();
          if (hints.hasClass('unloaded')) {
            hints.removeClass('unloaded');
          }
          resultWrapper.addClass('unloaded');
          btnClear.removeClass('visable');
          main.removeClass('hidden');

          input.val('');
          visable = false;

          scrollBlocker.release();
        }
      },
      isVisable: function() {
        return visable;
      }
    }
  })();


  function isMobileView() {
    return btnCancel.hasClass('loaded');
  }

  btnSearchTrigger.click(function() {
    mobileSearchBar.on();
    resultSwitch.on();
    input.focus();
  });

  btnCancel.click(function() {
    mobileSearchBar.off();
    resultSwitch.off();
  });

  input.focus(function() {
    searchWrapper.addClass('input-focus');
  });

  input.focusout(function() {
    searchWrapper.removeClass('input-focus');
  });

  input.on('keyup', function(e) {
    if (e.keyCode == 8 && input.val() == '') {
      if (!isMobileView()) {
        resultSwitch.off();
      } else {
        hints.removeClass('unloaded');
      }
    } else {
      if (input.val() != '') {
        resultSwitch.on();

        if (!btnClear.hasClass('visible')) {
          btnClear.addClass('visable');
        }

        if (isMobileView()) {
          hints.addClass('unloaded');
        }
      }
    }
  });

  btnClear.on('click', function() {
    input.val('');
    if (isMobileView()) {
      hints.removeClass('unloaded');
      results.empty();
    } else {
      resultSwitch.off();
    }
    input.focus();
    btnClear.removeClass('visable');
  });

});