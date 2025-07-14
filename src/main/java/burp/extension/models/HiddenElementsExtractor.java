package burp.extension.models;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HiddenElementsExtractor {
    public static List<String> extractHiddenElements(String html) {
        List<String> hiddenElements = new ArrayList<>();

        Pattern pattern = Pattern.compile(
            "<\\w+\\s+[^>]*?=[\"']?hidden[\"']?[^>]*?>",
            Pattern.CASE_INSENSITIVE
        );

        Matcher matcher = pattern.matcher(html);

        while (matcher.find()) {
            hiddenElements.add(matcher.group());
        }

        return hiddenElements;
    }
}
