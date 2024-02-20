#include <idc.idc>

static HideSelectedArea( void )
{
	auto start = SelStart();
	auto end = SelEnd();
	if ( BADADDR == start || BADADDR == end )
	{
		Warning( "no area selected" );
		return;
	}
	
	auto name = AskStr( "", "Enter an area name" );
	if ( "" == name || 0 == name )
	{
		Warning( "incorrect the area name" );
		return;
	}
	
	if ( HideArea( start, end, name, name + " start",
		name + " end", 0x00FFFFFF ) )
	{
//		SetHiddenArea( start, 0 );
	}
	else {
		Warning( "can't create the hidden area" );
	}
}

static main( void )
{
	AddHotkey( "ctrl-h", "HideSelectedArea" );
}
