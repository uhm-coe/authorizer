( function ( $ ) {
	/**
	 * Auto-growing textareas
	 * http://github.com/jaz303/jquery-grab-bag/tree/master/javascripts/jquery.autogrow-textarea.js
	 */
	$.fn.autogrow = function ( options ) {
		return this.filter( 'textarea' ).each( function () {
			var self = this;
			var $self = $( self );
			var minHeight = $self.height();
			var noFlickerPad = $self.hasClass( 'autogrow-short' ) ? 0 : parseInt( $self.css( 'lineHeight' ) ) || 0;
			var settings = $.extend({
				preGrowCallback: null,
				postGrowCallback: null,
			}, options );

			var shadow = $( '<div></div>' ).css({
				position: 'absolute',
				top: -10000,
				left: -10000,
				width: $self.width(),
				fontSize: $self.css('fontSize'),
				fontFamily: $self.css('fontFamily'),
				fontWeight: $self.css('fontWeight'),
				lineHeight: $self.css('lineHeight'),
				resize: 'none',
			}).appendTo( document.body );

			var update = function ( event ) {
				var times = function ( string, number ) {
					for ( var i = 0, r = ''; i < number; i++ ) {
						r += string;
					}
					return r;
				};

				var val = self.value.replace( /&/g, '&amp;' )
					.replace( /</g, '&lt;' )
					.replace( />/g, '&gt;' )
					.replace( /\n$/, '<br/>&#xa0;' )
					.replace( /\n/g, '<br/>' )
					.replace( / {2,}/g, function ( space ) { return times( '&#xa0;', space.length - 1 ) + ' ' });

				// Did enter get pressed?  Resize in this keydown event so that the flicker doesn't occur.
				if ( event && event.data && event.data.event === 'keydown' && event.keyCode === 13 && ! ( event.ctrlKey || event.altKey ) ) {
					val += '<br />';
				}

				shadow.css( 'width', $self.width() );
				shadow.html( val + ( noFlickerPad === 0 ? '...' : '' ) ); // Append '...' to resize preemptively.

				var newHeight = Math.max( shadow.height() + noFlickerPad, minHeight );
				if ( settings.preGrowCallback != null ) {
				  newHeight = settings.preGrowCallback( $self, shadow, newHeight, minHeight );
				}

				$self.height( newHeight );

				if ( settings.postGrowCallback != null ) {
				  settings.postGrowCallback( $self );
				}
			}

			$self.on( 'change', update ).on( 'keyup', update ).on( 'keydown', { event:'keydown' }, update );
			$( window ).on( 'resize', update );
			update();
		});
	};
})( jQuery );
