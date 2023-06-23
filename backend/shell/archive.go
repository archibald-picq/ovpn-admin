package shell

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func CreateArchiveFromDir(dir, path string) error {

	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf(err.Error())
			return err
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		log.Printf(err.Error())
	}

	out, err := os.Create(path)
	if err != nil {
		log.Printf("Error writing archive %s: %s", path, err)
		return err
	}
	defer out.Close()
	gw := gzip.NewWriter(out)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	// Iterate over files and add them to the tar archive
	for _, filePath := range files {
		file, err := os.Open(filePath)
		if err != nil {
			log.Printf("Error writing archive %s: %s", path, err)
			return err
		}

		// Get FileInfo about our file providing file size, mode, etc.
		info, err := file.Stat()
		if err != nil {
			file.Close()
			return err
		}

		// Create a tar Header from the FileInfo data
		header, err := tar.FileInfoHeader(info, info.Name())
		if err != nil {
			file.Close()
			return err
		}

		header.Name = strings.Replace(filePath, dir+"/", "", 1)

		// Write file header to the tar archive
		err = tw.WriteHeader(header)
		if err != nil {
			file.Close()
			return err
		}

		// Copy file content to tar archive
		_, err = io.Copy(tw, file)
		if err != nil {
			file.Close()
			return err
		}
		file.Close()
	}

	return nil
}

func ExtractFromArchive(archive, path string) error {
	// Open the file which will be written into the archive
	file, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write file header to the tar archive
	uncompressedStream, err := gzip.NewReader(file)
	if err != nil {
		log.Fatal("extractFromArchive(): NewReader failed")
	}

	tarReader := tar.NewReader(uncompressedStream)

	for true {
		header, err := tarReader.Next()

		if err == io.EOF {
			break
		}

		if err != nil {
			log.Fatalf("extractFromArchive: Next() failed: %s", err.Error())
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.Mkdir(path+"/"+header.Name, 0755); err != nil {
				log.Fatalf("extractFromArchive: Mkdir() failed: %s", err.Error())
			}
		case tar.TypeReg:
			outFile, err := os.Create(path + "/" + header.Name)
			if err != nil {
				log.Fatalf("extractFromArchive: Create() failed: %s", err.Error())
			}
			if _, err := io.Copy(outFile, tarReader); err != nil {
				log.Fatalf("extractFromArchive: Copy() failed: %s", err.Error())
			}
			outFile.Close()

		default:
			log.Fatalf(
				"extractFromArchive: uknown type: %s in %s", header.Typeflag, header.Name)
		}
	}
	return nil
}
