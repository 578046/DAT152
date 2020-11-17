package no.hvl.dat152.obl4.dictionary;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;

public class FileReaderUtil {

	public static String getWebFile(String webAdresse)
			throws MalformedURLException, IOException {

		StringBuffer innData = new StringBuffer();

		URL urlen = new URL(webAdresse);
		URLConnection urlc = urlen.openConnection();

		InputStream input = urlc.getInputStream();

		byte[] binaerData = new byte[1000];
		while (true) {
			int bytesLest = input.read(binaerData);
			if (bytesLest == -1)
				break;
			innData.append(new String(binaerData, 0, bytesLest));
		}
		input.close();

		return innData.toString();
	}
}