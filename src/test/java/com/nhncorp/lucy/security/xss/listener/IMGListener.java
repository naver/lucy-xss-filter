package com.nhncorp.lucy.security.xss.listener;

import com.nhncorp.lucy.security.xss.event.ElementListener;
import com.nhncorp.lucy.security.xss.markup.Element;

public class IMGListener implements ElementListener{

	public void handleElement(Element e) {
		
		String id = e.getAttributeValue("id");
		
		String srcValue = "'http://local.cafe.naver.com/MoviePlayer.nhn?dir="+id+"?key=";
		
		e.setName("iframe");
		
		boolean result = e.removeAllAttributes();
		if (result) {
			e.putAttribute("frameborder", "'no'");
			e.putAttribute("width", "342");
			e.putAttribute("height", "296");
			e.putAttribute("scrolling", "no");
			e.putAttribute("name", "'mplayer'");
			e.putAttribute("src", srcValue);
			
		}		
		e.setClose(true);
	}
}
