import { Marked } from 'marked';
import DOMPurify from 'dompurify';

const marked = new Marked({
	breaks: true,
	gfm: true
});

const MAX_RENDER_LENGTH = 64000; // 64KB input cap to prevent DOM explosion (M10)

export function renderMarkdown(content: string): string {
	const input = content.length > MAX_RENDER_LENGTH ? content.slice(0, MAX_RENDER_LENGTH) + '\n\n*[message truncated]*' : content;
	const html = marked.parse(input);
	if (typeof html !== 'string') return content;
	return DOMPurify.sanitize(html, { USE_PROFILES: { html: true } });
}
