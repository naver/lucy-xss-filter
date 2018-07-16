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
package com.nhncorp.lucy.security.xss.markup;

import java.io.IOException;
import java.io.Writer;

import org.apache.commons.lang3.StringUtils;

/**
 * @author Naver Labs
 */
public class IEHackExtensionElement extends Element {
	public IEHackExtensionElement(String name) {
		super(name);
	}

	@Override
	public void setName(String name) {
		throw new UnsupportedOperationException();
	}

	public void serialize(Writer writer) throws IOException {

		// IE에서 핵이 그대로 노출되는 문제 방지 및 공백제거처리
		String stdName = getName().replaceAll("-->", ">").replaceFirst("<!--\\s*", "<!--").replaceAll("]\\s*>", "]>");

		int startIndex = stdName.indexOf("<!") + 1;
		int lastIntndex = stdName.lastIndexOf(">");

		String firststdName = stdName.substring(0, startIndex);
		String middlestdName = StringUtils.replaceEach(stdName.substring(startIndex, lastIntndex), new String[] {"<", ">"}, new String[] {"&lt;", "&gt;"});
		String laststdName = stdName.substring(lastIntndex);

		stdName = firststdName + middlestdName + laststdName;

		writer.write(stdName);
	}
}
