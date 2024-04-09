import csv


def write_csv(file_name, data):  # data is a matrix
    with open(file_name, "w", newline='', encoding='utf-8') as f:
        wr = csv.writer(f)
        wr.writerows(data)


def read_csv(file_name):
    with open(file_name, "r", encoding='utf-8') as f:
        rd = csv.reader(f)
        return list(rd)
