package burp.extension.models;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class InlineJSExtractor {
    public static List<String> extractInlineJS(String html) {
        List<String> inlineJS = new ArrayList<>();

        Pattern pattern = Pattern.compile(
            "<script (.*?) </script>",
            Pattern.CASE_INSENSITIVE
        );

        Matcher matcher = pattern.matcher(html);

        while (matcher.find()) {
            inlineJS.add(matcher.group());
        }

        return inlineJS;
    }
}
