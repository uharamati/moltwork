import { Marked } from 'marked';
import DOMPurify from 'dompurify';

const marked = new Marked({
	breaks: true,
	gfm: true
});

export function renderMarkdown(content: string): string {
	const html = marked.parse(content);
	if (typeof html !== 'string') return content;
	return DOMPurify.sanitize(html, { USE_PROFILES: { html: true } });
}
