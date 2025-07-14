package burp.extension.models;

import java.util.regex.*;
import java.util.ArrayList;
import java.util.List;

public class CommentExtractor {
    public static List<String> extractHtmlComments(String html) {
        List<String> comments = new ArrayList<>();

        Pattern pattern = Pattern.compile("<!--(.*?)-->", Pattern.DOTALL);
        Matcher matcher = pattern.matcher(html);

        while (matcher.find()) {
            comments.add(matcher.group(1).trim());
        }

        return comments;
    }
}