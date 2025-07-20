class CSV:
    def __init__(self, *args):
        self.rows = []
        self.add_row(*args)

    def __str__(self):
        return '\n'.join(self.rows)

    def add_row(self, *args):
        row = []
        for value in args:
            escaped = str(value).replace('"', '""')
            row.append(f'"{escaped}"')
        self.rows.append(','.join(row))
