/*
 * @(#)CommonUtils.java $version 2012. 6. 29.
 *
 * Copyright 2007 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */

package com.nhncorp.lucy.security.xss;

/**
 * @author Naver Labs
 */
public class CommonUtils {
	/**
	 * 따음표의 짝을 맞춰준다.
	 * 
	 * @param text
	 * @return
	 */
	public static String getQuotePair(String text) {
		String quotePairStr = text;
		
		if ( "\"".equals(text)) {
			quotePairStr = "\"\"";
		} else if ( "'".equals(text)) {
			quotePairStr = "''";
		} else if ( text.startsWith("\"") && !text.endsWith("\"")) {
			quotePairStr = quotePairStr + "\"";
		} else if ( text.startsWith("'") && !text.endsWith("'")) {
			quotePairStr = quotePairStr + "'";
		} else if ( !text.startsWith("\"") && text.endsWith("\"")) {
			quotePairStr = "\"" + quotePairStr;
		} else if ( !text.startsWith("'") && text.endsWith("'")) {
			quotePairStr = "'" + quotePairStr;
		}
		
		return quotePairStr;
	}
}
