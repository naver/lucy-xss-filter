/*
 *	Copyright 2014 Naver Corp.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *		http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
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
