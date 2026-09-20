"Logitech G-15 Keyboard Layout"
{
	"game"		"Portal 2 July 2009"
	"chatlines"	"8"  // number of chat lines to keep (1-64)
	
	// These need to be 1bpp HICONs
	"icons"
	{
		"cssicon"			"resource/portal2_1bpp.ico"
	}

	// Applied to all text just before it is drawn.
	// Trims the useless ".000000" so vectors fit on the 160px screen.
	"replace"
	{
		".000000"	""
	}
		
	// title page is special
	"page"
	{
		// Special signal, this page is shown at startup and when disconnected from server
		"titlepage"		"1"
		
		"static_icon"
		{
			"x"			"0"
			"y"			"10"
			"name"		"cssicon"
		}
		
		"static_text"
		{
			"size"		"big"
			"align"		"center"
			"x"			"34"
			"y"			"10"
			"w"			"120"
			"text"		"Portal 2 Beta"
		}
			
		"static_text"
		{
			"size"		"medium"
			"align"		"center"
			"x"			"34"
			"y"			"25"
			"w"			"120"
			"text"		"July 2009"
		}
	}
	
	// Player debug page
	// Left G-key under the LCD = next page, second key = next subpage
	"page"   
	{
		// Only show this if the player has a player entity in the game
		"requiresplayer"	"1"

		"static_text"
		{
			"size"		"small"
			"align"		"left"
			"x"			"0"
			"y"			"0"
			"w"			"160"
			"text"		"P: %(localplayer)m_vecOrigin%"
		}

		"static_text"
		{
			"size"		"small"
			"align"		"left"
			"x"			"0"
			"y"			"10"
			"w"			"160"
			"text"		"V: %(localplayer)m_vecVelocity%"
		}

		"static_text"
		{
			"size"		"small"
			"align"		"left"
			"x"			"0"
			"y"			"20"
			"w"			"160"
			// pitch yaw roll (see notes: pitch is not the real view pitch)
			"text"		"A: %(localplayer)m_angRotation%"
		}

		"static_text"
		{
			"size"		"small"
			"align"		"left"
			"x"			"0"
			"y"			"30"
			"w"			"160"
			"text"		"(mapname)  T:(time_float)"
		}

	}
		
}
