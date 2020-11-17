package no.hvl.dat152.obl4.dictionary;

import java.util.ArrayList;
import java.util.List;

public class DictionaryParser {
	
	private String page;
	
	private boolean strict = true;

	public DictionaryParser(String page) {
		this.page = page;
	}
	
	public List<String> findMatchingEntries(String ord) {

		List<String> oppforinger = new ArrayList<String>();

		ord = ord.toUpperCase().charAt(0) + ord.toLowerCase().substring(1);
		String sokestreng = "<b>" + ord;
		if (strict) {
			sokestreng += "</b>";
		}

		int startIndex = 0;
		int endIndex = 0;
		while (startIndex >= 0) {

			startIndex = page.indexOf(sokestreng, endIndex);
			endIndex = page.indexOf("</p>", startIndex);

			if (startIndex >= 0 && endIndex > startIndex) {
				oppforinger.add(format(page.substring(startIndex, endIndex)));
			}
		}
		return oppforinger;
		
	}

	private String format(String string) {
		
		String resultat = string;
		resultat = resultat.replace("<b>", "");
		resultat = resultat.replace("</b>", "");
		resultat = resultat.replace("<i>", "");
		resultat = resultat.replace("</i>", "");
		
		return resultat;
	}

}
