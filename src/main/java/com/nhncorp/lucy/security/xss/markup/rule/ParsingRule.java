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
package com.nhncorp.lucy.security.xss.markup.rule;

/**
 * 이 클래스는 패키지 외부에서 참조 되지 않는다.
 * @author Naver Labs
 */
abstract class ParsingRule {
	public enum UNARY {
		OPTION, REPEAT0, REPEAT1, ONE;

		public static UNARY getValue(char ch) {
			switch (ch) {
				case '?':
					return OPTION;
				case '*':
					return REPEAT0;
				case '+':
					return REPEAT1;
			}
			return ONE;
		}
	}

	protected UNARY unary = UNARY.ONE;

	public UNARY getUnary() {
		return this.unary;
	}

	public void setUnary(UNARY unary) {
		this.unary = unary;
	}

	public boolean isOptional() {
		if (unary == UNARY.OPTION || unary == UNARY.REPEAT0) {
			return true;
		} else {
			return false;
		}
	}

	public boolean isRepeat() {
		if (this.getUnary() == UNARY.REPEAT0 || this.getUnary() == UNARY.REPEAT1) {
			return true;
		} else {
			return false;
		}
	}
}
